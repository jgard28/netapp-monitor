"""Terminal output: a grouped table or JSON."""
from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict

from . import intel
from .collector import SEVERITY_NAMES, reverse_dns, snapshot, visible_connections
from .detect import analyze

COLORS = {0: "", 1: "\033[33m", 2: "\033[38;5;208m", 3: "\033[31;1m"}
DIM, BOLD, RESET = "\033[2m", "\033[1m", "\033[0m"


def run(args) -> int:
    blocklist = intel.load(update=not args.offline)
    procs = analyze(snapshot(), blocklist)
    rows = [(p, visible_connections(p, args.all)) for p in procs]
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
            d["connections"] = [asdict(c) | {"host": hosts.get(c.raddr, "")} for c in conns]
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
            print("    " + paint(COLORS[a.severity], f"! {a.message}"))
        for c in conns:
            host = hosts.get(c.raddr, "")
            line = f"    {c.proto:<3}  {c.local:<22} -> {c.remote or '*':<22} {c.status:<11} {c.scope:<9} {host}"
            print(paint(COLORS[max((a.severity for a in c.alerts), default=0)], line.rstrip()))
            for a in c.alerts:
                print("        " + paint(COLORS[a.severity], f"! {a.message}"))
    flagged = sum(1 for p, _ in rows if p.severity)
    internet = sum(len(p.internet) for p in procs)
    print(paint(DIM, f"\n{len(rows)} apps shown, {internet} internet connections, "
                     f"{flagged} flagged; intel: {blocklist.summary()}"))
    return 0
