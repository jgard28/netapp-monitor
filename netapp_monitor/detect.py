"""Heuristics that flag processes and connections worth a closer look for malware or C2."""
from __future__ import annotations

import os
import re
import statistics
import time
from collections import defaultdict

from .collector import HIGH, LOW, MEDIUM, Alert, Connection, Process

SUSPICIOUS_PORTS = {
    1080: "SOCKS proxy",
    1337: "common backdoor port",
    3333: "crypto-mining pool",
    4444: "Metasploit default handler",
    4445: "Metasploit alternate handler",
    5555: "common RAT port",
    6666: "IRC / backdoor",
    6667: "IRC (classic botnet C2)",
    6697: "IRC over TLS (botnet C2)",
    9001: "Tor relay",
    9030: "Tor directory",
    9050: "Tor SOCKS",
    9150: "Tor Browser SOCKS",
    14444: "Monero mining pool",
    31337: "common backdoor port",
    45700: "Monero mining pool",
    50050: "Cobalt Strike team server",
}

SHELLS = {"sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh",
          "nc", "ncat", "netcat", "socat", "telnet"}
INTERPRETER = re.compile(r"(python|perl|ruby|php|node|lua|tclsh)[\d.]*$")
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")

HOME = os.path.expanduser("~")
# Hidden directories that commonly hold legitimate binaries.
HIDDEN_OK = tuple(f"{HOME}/{d}/" for d in (
    ".local", ".cargo", ".rustup", ".vscode", ".vscode-oss", ".cursor", ".nvm",
    ".npm", ".bun", ".deno", ".steam", ".mozilla", ".config", ".cache/uv", ".pyenv",
    ".claude", ".windsurf", ".antigravity", ".var/app",
))


def check_process(proc: Process) -> list[Alert]:
    alerts = []
    exe = proc.exe
    base = os.path.basename(exe) if exe else proc.name

    if proc.exe_deleted:
        alerts.append(Alert(MEDIUM, "Executable was deleted or replaced on disk while running "
                                    "(a malware trick, but also normal after an update until the app restarts)"))
    if exe.startswith(TEMP_DIRS):
        alerts.append(Alert(HIGH, f"Runs from a temp directory: {exe}"))
    elif "/." in exe and not exe.startswith(HIDDEN_OK) and "/.venv/" not in exe:
        alerts.append(Alert(LOW, f"Runs from a hidden directory: {exe}"))
    if proc.cmdline.startswith("[") and exe:
        alerts.append(Alert(HIGH, f"Disguised as a kernel thread: '{proc.cmdline}' is really {exe}", kind="never-mute"))

    if proc.internet:
        if base in SHELLS or proc.name in SHELLS:
            alerts.append(Alert(HIGH, f"{base} has an internet connection (possible reverse shell)"))
        elif INTERPRETER.match(base):
            alerts.append(Alert(LOW, f"Script interpreter talking to the internet: {proc.cmdline[:200]}"))
    return alerts


def check_connection(conn: Connection, blocklist: dict) -> list[Alert]:
    alerts = []
    hit = blocklist.get(conn.raddr) if conn.raddr else None
    if hit:
        alerts.append(Alert(hit.severity, hit.describe(conn.rport), kind="intel"))
    if conn.scope == "internet" and conn.rport in SUSPICIOUS_PORTS:
        alerts.append(Alert(MEDIUM, f"Remote port {conn.rport}: {SUSPICIOUS_PORTS[conn.rport]}"))
    elif conn.scope == "listening" and conn.status == "LISTEN" and conn.lport in SUSPICIOUS_PORTS:
        alerts.append(Alert(MEDIUM, f"Listening on port {conn.lport}: {SUSPICIOUS_PORTS[conn.lport]}"))
    return alerts


class BeaconTracker:
    """Spots processes that open fresh connections to the same host at a steady rhythm.

    C2 implants usually "check in" on a timer. Each new connection to a destination is
    recorded; once there are enough of them, low jitter between the gaps is flagged.
    Connections shorter than the sampling interval can be missed.
    """

    def __init__(self, min_events=5, max_jitter=0.2, min_interval=5.0, window=3600):
        self.min_events = min_events
        self.max_jitter = max_jitter
        self.min_interval = min_interval
        self.window = window
        self.events: dict[tuple, list[float]] = defaultdict(list)
        self.seen: set[tuple] = set()

    def observe(self, procs: list[Process], now: float | None = None):
        now = time.time() if now is None else now
        current = set()
        for p in procs:
            for c in p.internet:
                current.add(c.key)
                if c.key not in self.seen:
                    self.events[(p.exe or p.name, c.raddr, c.rport)].append(now)
        # Forget closed connections so a reconnect from the same local port counts again.
        self.seen = current
        cutoff = now - self.window
        for k in list(self.events):
            kept = [t for t in self.events[k] if t >= cutoff]
            if kept:
                self.events[k] = kept
            else:
                del self.events[k]

    def interval(self, exe: str, raddr: str, rport: int) -> float | None:
        events = self.events.get((exe, raddr, rport), [])
        if len(events) < self.min_events:
            return None
        gaps = [b - a for a, b in zip(events, events[1:])]
        mean = statistics.mean(gaps)
        if mean < self.min_interval:
            return None
        return mean if statistics.pstdev(gaps) / mean <= self.max_jitter else None


def analyze(procs: list[Process], blocklist: dict | None = None,
            tracker: BeaconTracker | None = None, trust=None, baseline=None) -> list[Process]:
    """Attach alerts and "new" tags to every process and connection, then sort the worst first."""
    blocklist = blocklist or {}
    if tracker:
        tracker.observe(procs)
    for p in procs:
        p.alerts = check_process(p)
        for c in p.connections:
            c.alerts = check_connection(c, blocklist)
            if tracker and c.scope == "internet":
                every = tracker.interval(p.exe or p.name, c.raddr, c.rport)
                if every:
                    c.alerts.append(Alert(MEDIUM, f"Beaconing: reconnects every ~{every:.0f}s"))
    if trust:
        trust.apply(procs)
    if baseline:
        baseline.observe(procs)
    procs.sort(key=lambda p: (-p.severity, -len(p.internet), p.name.lower()))
    return procs
