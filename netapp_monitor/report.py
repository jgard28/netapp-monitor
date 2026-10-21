"""A snapshot report of connections, alerts and program fingerprints, as JSON or a standalone HTML page.

Useful as evidence, or to hand to someone helping you investigate. It contains IP addresses,
command lines and your hostname, so look it over before sharing.
"""
from __future__ import annotations

import getpass
import html
import json
import socket
import time

from . import appinfo
from .collector import SEVERITY_NAMES, Process, human_bytes, local_kind, severity_of
from .explain import explain

RECENT_ALERTS = 24 * 3600


def _program_facts(exe: str, cached: dict | None) -> dict:
    """Package, hash and integrity for a program, reusing the dashboard's lookups when it has them."""
    if cached:
        return {"package": cached.get("package"), "sha256": cached.get("sha256"),
                "matches_package": cached.get("exe_matches")}
    facts = {"package": None, "sha256": None, "matches_package": None}
    if not exe:
        return facts
    facts["package"] = appinfo.owning_package(exe)
    try:
        facts["sha256"] = appinfo.sha256(exe)
        recorded = appinfo.packaged_hash(exe, facts["package"]) if facts["package"] else None
        if recorded:
            algo, digest = recorded
            actual = facts["sha256"] if algo == "sha256" else appinfo.file_hash(exe, algo)
            facts["matches_package"] = actual == digest
    except OSError:
        pass
    return facts


def _alert(a) -> dict:
    why = explain(a.topic)
    return {"severity": SEVERITY_NAMES[a.severity], "message": a.message, "muted": a.muted,
            "topic": a.topic, "explanation": why.short if why else ""}


def build(procs: list[Process], *, intel_summary: str = "", dns_status: str = "", history=None,
          cache=None, blocked=(), always=None, trust=None, now: float | None = None) -> dict:
    """Everything worth keeping about this moment, as plain data.

    `cache(exe)` returns the dashboard's already-computed program facts, if any.
    """
    now = time.time() if now is None else now
    apps = []
    for p in procs:
        conns = [c for c in p.connections if c.scope == "internet" or c.local_device or c.alerts]
        if not conns and not p.alerts:
            continue
        facts = _program_facts(p.exe, cache(p.exe) if cache and p.exe else None)
        apps.append({
            "name": p.name, "pid": p.pid, "pids": p.pids or ([p.pid] if p.pid else []), "user": p.user,
            "exe": p.exe, "exe_deleted": p.exe_deleted, "cmdline": p.cmdline, **facts,
            "severity": SEVERITY_NAMES[p.severity], "new": p.has_new,
            "alerts": [_alert(a) for a in p.alerts],
            "connections": [{
                "proto": c.proto, "local": c.local, "remote": c.remote, "scope": c.scope, "state": c.status,
                "host": c.device or c.domain, "new": c.new,
                "network": c.owner.label() if c.owner else (local_kind(c.raddr) if c.raddr else ""),
                "asn": c.owner.asn if c.owner else None,
                "sent": c.sent, "received": c.received,
                "severity": SEVERITY_NAMES[severity_of(c.alerts)],
                "alerts": [_alert(a) for a in c.alerts],
            } for c in conns],
        })
    flagged = [a for a in apps if a["severity"] != "ok"]
    return {
        "tool": "NetApp Monitor",
        "generated": time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(now)),
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "intel": intel_summary,
        "dns": dns_status,
        "summary": {
            "apps": len(apps), "flagged": len(flagged),
            "internet_connections": sum(len(p.internet) for p in procs),
            "local_connections": sum(len(p.local) for p in procs),
        },
        "apps": apps,
        "recent_alerts": history.alerts(now - RECENT_ALERTS) if history else [],
        "blocked": list(blocked),
        "always_blocked": sorted(always or {}),
        "trusted": {"apps": sorted(trust.apps), "destinations": sorted(trust.destinations)} if trust else {},
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)


CSS = """
:root { --bg:#ffffff; --fg:#1f2328; --muted:#656d76; --line:#d0d7de; --card:#f6f8fa;
        --ok:#1a7f37; --low:#9a6700; --medium:#bc4c00; --high:#cf222e; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#8b949e; --line:#30363d; --card:#161b22;
          --ok:#3fb950; --low:#d29922; --medium:#f0883e; --high:#f85149; }
}
body { background:var(--bg); color:var(--fg); font:14px/1.5 system-ui, sans-serif; margin:0 auto;
       max-width:1100px; padding:24px 16px; }
h1 { margin:0 0 4px; font-size:22px; } h2 { margin:32px 0 8px; font-size:17px; }
.meta, .muted { color:var(--muted); }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin:16px 0; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:10px 14px; min-width:120px; }
.card b { display:block; font-size:22px; }
.app { background:var(--card); border:1px solid var(--line); border-left:4px solid var(--line);
       border-radius:8px; padding:12px 14px; margin:12px 0; }
.app.sev-high { border-left-color:var(--high); } .app.sev-medium { border-left-color:var(--medium); }
.app.sev-low { border-left-color:var(--low); }
.app h3 { margin:0 0 6px; font-size:15px; }
.high { color:var(--high); } .medium { color:var(--medium); } .low { color:var(--low); } .ok { color:var(--ok); }
.app h3 .high, .app h3 .medium, .app h3 .low { font-size:12px; text-transform:uppercase; margin-left:6px; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:2px 12px; margin:6px 0; }
dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
code { font-size:12px; overflow-wrap:anywhere; }
table { border-collapse:collapse; width:100%; margin:6px 0; font-size:13px; }
th, td { text-align:left; padding:4px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; }
.scroll { overflow-x:auto; }
ul.alerts { margin:6px 0; padding-left:18px; }
footer { margin-top:40px; color:var(--muted); font-size:12px; }
"""


def _sev(name: str, text: str | None = None) -> str:
    return f"<span class='{name}'>{html.escape(text or name)}</span>"


def _alerts_html(alerts) -> str:
    if not alerts:
        return ""
    items = []
    for a in alerts:
        muted = " <span class='muted'>(muted)</span>" if a["muted"] else ""
        why = f"<br><span class='muted'>{html.escape(a['explanation'])}</span>" if a["explanation"] else ""
        items.append(f"<li>{_sev('muted' if a['muted'] else a['severity'], a['message'])}{muted}{why}</li>")
    return "<ul class='alerts'>" + "".join(items) + "</ul>"


def _connections_table(conns) -> str:
    rows = []
    for c in conns:
        data = f"↑ {human_bytes(c['sent'])} ↓ {human_bytes(c['received'])}" if c["sent"] or c["received"] else ""
        alerts = "; ".join(a["message"] for a in c["alerts"])
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(v))}</td>" for v in (
            c["proto"], c["remote"] or c["local"], c["host"], c["network"], c["state"], data)) +
            f"<td>{_sev(c['severity'], alerts) if alerts else ''}</td></tr>")
    head = "".join(f"<th>{h}</th>" for h in ("Proto", "Remote", "Host", "Network", "State", "Data", "Alerts"))
    return f"<div class='scroll'><table><tr>{head}</tr>{''.join(rows)}</table></div>"


def to_html(report: dict) -> str:
    esc = html.escape
    s = report["summary"]
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
           f"<title>NetApp Monitor report</title><style>{CSS}</style></head><body>",
           "<h1>NetApp Monitor report</h1>",
           f"<div class='meta'>{esc(report['host'])} · {esc(report['user'])} · {esc(report['generated'])}</div>",
           "<div class='cards'>"]
    for label, value, cls in (("Apps online", s["apps"], ""), ("Flagged", s["flagged"], "high" if s["flagged"] else "ok"),
                              ("Internet connections", s["internet_connections"], ""),
                              ("Local connections", s["local_connections"], "")):
        out.append(f"<div class='card'><b class='{cls}'>{value}</b>{label}</div>")
    out.append("</div>")
    out.append(f"<div class='muted'>Threat intel: {esc(report['intel'] or 'not loaded')} · "
               f"{esc(report['dns'] or '')}</div>")

    flagged = [a for a in report["apps"] if a["severity"] != "ok"]
    out.append(f"<h2>Flagged apps ({len(flagged)})</h2>")
    if not flagged:
        out.append("<p class='ok'>✔ Nothing flagged at the time of this report.</p>")
    for app in flagged:
        integrity = {True: _sev("ok", "✔ matches its package"), False: _sev("high", "✖ differs from its package"),
                     None: "<span class='muted'>not checked (no package record)</span>"}[app["matches_package"]]
        pids = ", ".join(map(str, app["pids"])) or "—"
        out.append(f"<div class='app sev-{app['severity']}'><h3>{esc(app['name'])}{_sev(app['severity'])}</h3>"
                   "<dl>"
                   f"<dt>Path</dt><dd><code>{esc(app['exe'] or 'unknown')}</code>"
                   f"{' (deleted on disk)' if app['exe_deleted'] else ''}</dd>"
                   f"<dt>Command</dt><dd><code>{esc(app['cmdline'][:600] or '—')}</code></dd>"
                   f"<dt>PID</dt><dd>{esc(pids)}</dd><dt>User</dt><dd>{esc(app['user'] or '?')}</dd>"
                   f"<dt>Package</dt><dd>{esc(app['package'] or 'none (not installed by a package manager)')}</dd>"
                   f"<dt>Integrity</dt><dd>{integrity}</dd>"
                   f"<dt>SHA-256</dt><dd><code>{esc(app['sha256'] or '—')}</code></dd>"
                   "</dl>" + _alerts_html(app["alerts"]) + _connections_table(app["connections"]) + "</div>")

    others = [a for a in report["apps"] if a["severity"] == "ok"]
    out.append(f"<h2>Other apps online ({len(others)})</h2>")
    if others:
        out.append("<div class='scroll'><table><tr><th>App</th><th>PID</th><th>Package</th><th>Connections</th>"
                   "<th>Talking to</th></tr>")
        for app in others:
            nets = sorted({c["host"] or c["network"] for c in app["connections"] if c["host"] or c["network"]})
            out.append(f"<tr><td title='{esc(app['exe'])}'>{esc(app['name'])}</td><td>{esc(str(app['pid'] or ''))}</td>"
                       f"<td>{esc(app['package'] or '—')}</td><td>{len(app['connections'])}</td>"
                       f"<td>{esc(', '.join(nets[:6]) + (' …' if len(nets) > 6 else ''))}</td></tr>")
        out.append("</table></div>")

    recent = report["recent_alerts"]
    out.append(f"<h2>Alerts in the last 24 hours ({len(recent)})</h2>")
    if recent:
        out.append("<div class='scroll'><table><tr><th>Time</th><th>Severity</th><th>App</th><th>Alert</th>"
                   "<th>Remote</th></tr>")
        for r in recent[:500]:
            sev = SEVERITY_NAMES.get(r["severity"], "")
            remote = f"{r['raddr']}:{r['rport']}" if r["raddr"] else ""
            out.append(f"<tr><td>{time.strftime('%b %d %H:%M', time.localtime(r['time']))}</td>"
                       f"<td>{_sev('muted' if r['muted'] else sev, sev)}</td><td>{esc(r['name'])}</td>"
                       f"<td>{esc(r['message'])}</td><td>{esc(remote)}</td></tr>")
        out.append("</table></div>")
    else:
        out.append("<p class='muted'>None recorded.</p>")

    if report["blocked"] or report["always_blocked"] or report["trusted"]:
        out.append("<h2>Settings</h2><dl>")
        out.append(f"<dt>Blocked now</dt><dd>{esc(', '.join(report['blocked']) or 'nothing')}</dd>")
        out.append(f"<dt>Always blocked</dt><dd>{esc(', '.join(report['always_blocked']) or 'nothing')}</dd>")
        trusted = report["trusted"] or {}
        out.append(f"<dt>Trusted apps</dt><dd>{esc(', '.join(trusted.get('apps', [])) or 'none')}</dd>")
        out.append(f"<dt>Trusted destinations</dt><dd>{esc(', '.join(trusted.get('destinations', [])) or 'none')}</dd>")
        out.append("</dl>")

    out.append("<footer>Generated by NetApp Monitor (https://github.com/jgard28/netapp-monitor). This report "
               "contains IP addresses, command lines and the computer's name; review it before sharing.</footer>"
               "</body></html>")
    return "\n".join(out)


def save(report: dict, path: str):
    text = to_json(report) if path.lower().endswith(".json") else to_html(report)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
