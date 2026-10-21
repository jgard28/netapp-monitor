"""A local timeline of internet connections and alerts, so you can look back after the fact.

Stored in SQLite under ~/.local/state/netapp-monitor/history.db and kept for 30 days. Each
internet connection becomes one row when it opens and is updated until it closes; each alert
is logged when it first appears (and again if it's still around an hour later).
"""
from __future__ import annotations

import re
import sqlite3
import time
from pathlib import Path

from .collector import Process, severity_of
from .memory import STATE_DIR

KEEP_DAYS = 30
FLUSH_EVERY = 60  # seconds between writing updates for connections that are still open
ALERT_REPEAT = 3600  # an alert still present after this long is logged again

SCHEMA = """
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY, app TEXT, name TEXT, pid INTEGER, proto TEXT, raddr TEXT, rport INTEGER,
    domain TEXT, country TEXT, owner TEXT, first REAL, last REAL, sent INTEGER, received INTEGER,
    severity INTEGER, alerts TEXT);
CREATE INDEX IF NOT EXISTS connections_last ON connections(last);
CREATE INDEX IF NOT EXISTS connections_app ON connections(app, last);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY, time REAL, app TEXT, name TEXT, pid INTEGER, severity INTEGER,
    message TEXT, topic TEXT, raddr TEXT, rport INTEGER, domain TEXT, muted INTEGER);
CREATE INDEX IF NOT EXISTS alerts_time ON alerts(time);
CREATE INDEX IF NOT EXISTS alerts_app ON alerts(app, time);
"""


class History:
    def __init__(self, path: Path | None = None):
        self.path = path or STATE_DIR / "history.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.open: dict[tuple, list] = {}  # connection key -> [row id, latest values]
        self.alerted: dict[tuple, float] = {}
        self.flushed = 0.0
        self.prune()

    def prune(self, now: float | None = None):
        cutoff = (time.time() if now is None else now) - KEEP_DAYS * 86400
        with self.db:
            self.db.execute("DELETE FROM connections WHERE last < ?", (cutoff,))
            self.db.execute("DELETE FROM alerts WHERE time < ?", (cutoff,))

    def record(self, procs: list[Process], now: float | None = None):
        now = time.time() if now is None else now
        current = {}
        with self.db:
            for p in procs:
                app = p.exe or p.name
                for c in p.internet:
                    key = (p.pid, app, c.proto, c.laddr, c.lport, c.raddr, c.rport)
                    owner = c.owner
                    values = {"domain": c.domain, "country": owner.country if owner else "",
                              "owner": owner.org if owner else "", "last": now, "sent": c.sent,
                              "received": c.received, "severity": severity_of(c.alerts),
                              "alerts": "; ".join(a.message for a in c.alerts if not a.muted)}
                    entry = self.open.get(key)
                    if entry is None:
                        cur = self.db.execute(
                            "INSERT INTO connections (app, name, pid, proto, raddr, rport, first, domain, country,"
                            " owner, last, sent, received, severity, alerts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (app, p.name, p.pid, c.proto, c.raddr, c.rport, now, *values.values()))
                        entry = [cur.lastrowid, values]
                    else:
                        # Keep what we learned earlier if this snapshot lacks it (e.g. the DNS name).
                        for field in ("domain", "country", "owner", "alerts"):
                            values[field] = values[field] or entry[1][field]
                        values["severity"] = max(values["severity"], entry[1]["severity"])
                        entry[1] = values
                    current[key] = entry
                for a in p.all_alerts():
                    conn = next((c for c in p.connections if a in c.alerts), None)
                    akey = (app, re.sub(r"\d+", "#", a.message), conn.raddr if conn else None)
                    if akey in self.alerted and now - self.alerted[akey] < ALERT_REPEAT:
                        continue
                    self.alerted[akey] = now
                    self.db.execute(
                        "INSERT INTO alerts (time, app, name, pid, severity, message, topic, raddr, rport, domain,"
                        " muted) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (now, app, p.name, p.pid, a.severity, a.message, a.topic, conn.raddr if conn else None,
                         conn.rport if conn else None, conn.domain if conn else "", int(a.muted)))
            closed = [entry for key, entry in self.open.items() if key not in current]
            due = now - self.flushed >= FLUSH_EVERY
            for entry in closed + (list(current.values()) if due else []):
                self._update(entry)
            if due:
                self.flushed = now
                self.alerted = {k: t for k, t in self.alerted.items() if now - t < ALERT_REPEAT}
        self.open = current

    def _update(self, entry):
        rowid, v = entry
        self.db.execute("UPDATE connections SET domain=?, country=?, owner=?, last=?, sent=?, received=?, "
                        "severity=?, alerts=? WHERE id=?",
                        (v["domain"], v["country"], v["owner"], v["last"], v["sent"], v["received"],
                         v["severity"], v["alerts"], rowid))

    def close(self):
        with self.db:
            for entry in self.open.values():
                self._update(entry)
        self.db.close()

    # --- queries ----------------------------------------------------------------

    def destinations(self, since: float, needle: str = "") -> list[dict]:
        """One row per app and destination seen since `since`, most recent first."""
        like = f"%{needle.lower()}%"
        rows = self.db.execute(
            "SELECT app, MAX(name), raddr, rport, MAX(domain), MAX(country), MAX(owner), COUNT(*), MIN(first),"
            " MAX(last), SUM(sent), SUM(received), MAX(severity), MAX(alerts) FROM connections"
            " WHERE last >= ? AND (? = '%%' OR lower(app || ' ' || name || ' ' || raddr || ' ' ||"
            " coalesce(domain, '') || ' ' || coalesce(owner, '')) LIKE ?)"
            " GROUP BY app, raddr, rport ORDER BY MAX(last) DESC LIMIT 5000",
            (since, like, like)).fetchall()
        keys = ("app", "name", "raddr", "rport", "domain", "country", "owner", "count", "first", "last",
                "sent", "received", "severity", "alerts")
        return [dict(zip(keys, r)) for r in rows]

    def alerts(self, since: float, needle: str = "") -> list[dict]:
        like = f"%{needle.lower()}%"
        rows = self.db.execute(
            "SELECT time, app, name, pid, severity, message, topic, raddr, rport, domain, muted FROM alerts"
            " WHERE time >= ? AND (? = '%%' OR lower(app || ' ' || name || ' ' || message || ' ' ||"
            " coalesce(raddr, '') || ' ' || coalesce(domain, '')) LIKE ?)"
            " ORDER BY time DESC LIMIT 5000",
            (since, like, like)).fetchall()
        keys = ("time", "app", "name", "pid", "severity", "message", "topic", "raddr", "rport", "domain", "muted")
        return [dict(zip(keys, r)) for r in rows]

    def app_summary(self, app: str, since: float) -> tuple[int, int]:
        """(distinct destinations, alerts) for one app since `since`."""
        dests = self.db.execute("SELECT COUNT(DISTINCT raddr) FROM connections WHERE app = ? AND last >= ?",
                                (app, since)).fetchone()[0]
        alerts = self.db.execute("SELECT COUNT(*) FROM alerts WHERE app = ? AND time >= ? AND muted = 0",
                                 (app, since)).fetchone()[0]
        return dests, alerts
