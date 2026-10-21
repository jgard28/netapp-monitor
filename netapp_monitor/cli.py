"""Terminal output: a grouped table or JSON."""
from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict

from . import blockctl, intel, report
from .collector import (SEVERITY_NAMES, local_kind, merge_shared, reverse_dns, severity_of, snapshot,
                        visible_connections)
from .detect import analyze
from .geo import GeoDB
from .memory import Trust

COLORS = {0: "", 1: "\033[33m", 2: "\033[38;5;208m", 3: "\033[31;1m"}
DIM, BOLD, RESET = "\033[2m", "\033[1m", "\033[0m"


def save_report(path, procs, blocklist, trust) -> int:
    from .history import History
    try:
        history = History()
    except Exception:  # sqlite errors: the report is still useful without the timeline
        history = None
    data = report.build(procs, intel_summary=blocklist.summary(), history=history, trust=trust,
                        always=blockctl.always_blocked())
    try:
        report.save(data, path)
    except OSError as e:
        print(f"netapp-monitor: could not save the report: {e}", file=sys.stderr)
        return 1
    s = data["summary"]
    print(f"Saved {path}: {s['apps']} apps, {s['flagged']} flagged, {len(data['recent_alerts'])} alerts in the last 24 h.")
    print("It contains IP addresses, command lines and this computer's name; review it before sharing.")
    return 0


def run(args) -> int:
    blocklist = intel.load(update=not args.offline)
    geo = GeoDB(update=not args.offline, background=False)
    trust = Trust()
    procs = analyze(snapshot(), blocklist, trust=trust, geo=geo)
    if args.report:
        return save_report(args.report, merge_shared(procs), blocklist, trust)
    rows = [(p, visible_connections(p, "all" if args.all else "local" if args.lan else "internet")) for p in procs]
    rows = [(p, conns) for p, conns in rows if conns or p.alerts]
    if args.alerts:
        rows = [(p, conns) for p, conns in rows if p.severity]

    hosts = {}
    if args.resolve:
        ips = {c.raddr for _, conns in rows for c in conns if c.raddr}
        with ThreadPoolExecutor(16) as pool:
            hosts = dict(zip(ips, pool.map(reverse_dns, ips)))

    if args.json:
        out = []
        for p, conns in rows:
            d = asdict(p)
            d["connections"] = [asdict(c) | {"host": hosts.get(c.raddr, ""),
                                             "owner": asdict(c.owner) if c.owner else None} for c in conns]
            d["severity"] = SEVERITY_NAMES[p.severity]
            out.append(d)
        json.dump(out, sys.stdout, indent=2)
        print()
        return 0

    color = sys.stdout.isatty()
    paint = (lambda code, s: f"{code}{s}{RESET}" if code else s) if color else (lambda code, s: s)
    for p, conns in rows:
        sev = f"  [{SEVERITY_NAMES[p.severity]}]" if p.severity else ""
        print(paint(COLORS[p.severity] or BOLD, f"{p.name} (pid {p.pid}, {p.user or '?'}){sev}"),
              paint(DIM, p.exe))
        for a in p.alerts:
            print("    " + paint(DIM if a.muted else COLORS[a.severity], f"! {'(muted) ' if a.muted else ''}{a.message}"))
        for c in conns:
            host = hosts.get(c.raddr, "")
            owner = c.owner.label() if c.owner else local_kind(c.raddr) if c.raddr and c.scope != "internet" else ""
            line = f"    {c.proto:<3}  {c.local:<22} -> {c.remote or '*':<22} {c.status:<11} {c.scope:<9} {owner:<34} {host}"
            print(paint(COLORS[severity_of(c.alerts)], line.rstrip()))
            for a in c.alerts:
                print("        " + paint(DIM if a.muted else COLORS[a.severity], f"! {'(muted) ' if a.muted else ''}{a.message}"))
    flagged = sum(1 for p, _ in rows if p.severity)
    internet = sum(len(p.internet) for p in procs)
    print(paint(DIM, f"\n{len(rows)} apps shown, {internet} internet connections, "
                     f"{flagged} flagged; intel: {blocklist.summary()}"))
    return 0
