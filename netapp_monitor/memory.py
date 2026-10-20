"""What NetApp Monitor remembers between runs: what you trust, and what it has seen before."""
from __future__ import annotations

import ipaddress
import json
import os
import time
from pathlib import Path

from .collector import HIGH, Process

STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "netapp-monitor"


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _save(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(path)


class Trust:
    """Apps (by executable path) and destinations (by IP) whose alerts you've muted.

    Muted alerts stay visible, greyed out, but no longer color the tray, pop up or sort
    an app to the top. A known C2 server from threat intel is never muted, nor is a process
    disguised as a kernel thread: a trusted app doing either is what a hijacked app looks like.
    """

    def __init__(self, path: Path | None = None):
        self.path = path or STATE_DIR / "trust.json"
        data = _load(self.path)
        self.apps: dict[str, float] = data.get("apps", {})
        self.destinations: dict[str, float] = data.get("destinations", {})

    def save(self):
        _save(self.path, {"apps": self.apps, "destinations": self.destinations})

    def set_app(self, exe: str, trusted: bool):
        self._set(self.apps, exe, trusted)

    def set_destination(self, ip: str, trusted: bool):
        self._set(self.destinations, ip, trusted)

    def _set(self, table, key, trusted):
        if trusted:
            table.setdefault(key, time.time())
        else:
            table.pop(key, None)
        self.save()

    def __len__(self):
        return len(self.apps) + len(self.destinations)

    def apply(self, procs: list[Process]):
        for p in procs:
            app_trusted = bool(p.exe) and p.exe in self.apps
            for a in p.alerts:
                a.muted = app_trusted and a.kind != "never-mute"
            for c in p.connections:
                dest_trusted = bool(c.raddr) and c.raddr in self.destinations
                for a in c.alerts:
                    never_mute = a.kind == "intel" and a.severity >= HIGH
                    a.muted = (app_trusted or dest_trusted) and not never_mute


def network_key(ip: str) -> str:
    """Group addresses by network so a CDN rotating IPs isn't 'new' every few minutes."""
    addr = ipaddress.ip_address(ip)
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


class Baseline:
    """Learns which apps reach the internet and where, and tags first contacts as new.

    Everything seen during the first `learning` seconds is treated as normal, so the first
    run doesn't tag the whole system. After that, an app's first internet connection, or
    its first connection to a network it has never talked to, is tagged new for `new_for`.
    """

    def __init__(self, path: Path | None = None, learning: float = 30 * 60, new_for: float = 24 * 3600):
        self.path = path or STATE_DIR / "baseline.json"
        data = _load(self.path)
        self.created: float = data.get("created", time.time())
        self.apps: dict[str, dict] = data.get("apps", {})  # exe -> {"first": ts, "dests": {net: ts}}
        self.learning = learning
        self.new_for = new_for
        self.dirty = not self.path.exists()
        self.saved_at = 0.0

    def learning_left(self, now: float | None = None) -> float:
        now = time.time() if now is None else now
        return max(0.0, self.created + self.learning - now)

    def observe(self, procs: list[Process], now: float | None = None):
        now = time.time() if now is None else now
        # First contacts during learning are recorded as "always known" (timestamp 0).
        stamp = 0.0 if self.learning_left(now) else now
        for p in procs:
            if p.pid is None or not p.internet:
                continue
            app = self.apps.get(p.exe or p.name)
            if app is None:
                app = self.apps[p.exe or p.name] = {"first": stamp, "dests": {}}
                self.dirty = True
            p.new = now - app["first"] < self.new_for
            for c in p.internet:
                net = network_key(c.raddr)
                if net not in app["dests"]:
                    app["dests"][net] = stamp
                    self.dirty = True
                c.new = now - app["dests"][net] < self.new_for
        if self.dirty and now - self.saved_at > 60:
            self.save(now)

    def save(self, now: float | None = None):
        _save(self.path, {"created": self.created, "apps": self.apps})
        self.dirty = False
        self.saved_at = time.time() if now is None else now
