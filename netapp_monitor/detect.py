"""Heuristics that flag processes and connections worth a closer look for malware or C2."""
from __future__ import annotations

import os
import re
import statistics
import time
from collections import defaultdict

from .collector import HIGH, LOW, MEDIUM, Alert, Connection, Process, human_bytes
from .dns import looks_generated, registrable

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
# Programs whose job is DNS; anyone else talking DNS straight to the internet is bypassing the resolver.
RESOLVERS = {"systemd-resolve", "systemd-resolved", "dnsmasq", "unbound", "named", "dnscrypt-proxy",
             "stubby", "tailscaled", "NetworkManager", "pihole-FTL", "coredns", "kresd"}

# Domains registered more recently than this are flagged (medium under a week, low under a month).
NEW_DOMAIN_DAYS = 30
VERY_NEW_DOMAIN_DAYS = 7

# Sending this much to the internet within UPLOAD_WINDOW seconds raises a (low) upload alert.
UPLOAD_LIMIT = 200 * 1000 * 1000
UPLOAD_WINDOW = 600

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
                                    "(a malware trick, but also normal after an update until the app restarts)", topic="deleted"))
    if exe.startswith(TEMP_DIRS):
        alerts.append(Alert(HIGH, f"Runs from a temp directory: {exe}", topic="temp"))
    elif "/." in exe and not exe.startswith(HIDDEN_OK) and "/.venv/" not in exe:
        alerts.append(Alert(LOW, f"Runs from a hidden directory: {exe}", topic="hidden"))
    if proc.cmdline.startswith("[") and exe:
        alerts.append(Alert(HIGH, f"Disguised as a kernel thread: '{proc.cmdline}' is really {exe}", kind="never-mute",
                            topic="kthread"))

    if proc.internet:
        if base in SHELLS or proc.name in SHELLS:
            alerts.append(Alert(HIGH, f"{base} has an internet connection (possible reverse shell)", topic="shell"))
        elif INTERPRETER.match(base):
            alerts.append(Alert(LOW, f"Script interpreter talking to the internet: {proc.cmdline[:200]}",
                                topic="interpreter"))
        if proc.name not in RESOLVERS and base not in RESOLVERS:
            direct = sorted({c.raddr for c in proc.internet if c.rport in (53, 853)})
            if direct:
                alerts.append(Alert(LOW, f"Does its own DNS, bypassing the system resolver ({', '.join(direct[:3])})",
                                    topic="dns-bypass"))
    return alerts


def check_connection(conn: Connection, blocklist: dict) -> list[Alert]:
    alerts = []
    hit = blocklist.get(conn.raddr) if conn.raddr else None
    if hit:
        alerts.append(Alert(hit.severity, hit.describe(conn.rport), kind="intel", topic="intel"))
    domain_hit = blocklist.domain_hit(conn.domain) if conn.domain and hasattr(blocklist, "domain_hit") else None
    if domain_hit and domain_hit is not hit:
        alerts.append(Alert(domain_hit.severity, f"{conn.domain}: {domain_hit.describe()}", kind="intel",
                            topic="intel-domain"))
    if conn.domain and conn.scope == "internet" and looks_generated(conn.domain):
        alerts.append(Alert(LOW, f"{conn.domain} looks randomly generated (a trait of malware domain generators)",
                            topic="dga"))
    if conn.scope == "internet" and conn.rport in SUSPICIOUS_PORTS:
        alerts.append(Alert(MEDIUM, f"Remote port {conn.rport}: {SUSPICIOUS_PORTS[conn.rport]}", topic="port"))
    elif conn.scope == "listening" and conn.status == "LISTEN" and conn.lport in SUSPICIOUS_PORTS:
        alerts.append(Alert(MEDIUM, f"Listening on port {conn.lport}: {SUSPICIOUS_PORTS[conn.lport]}", topic="listen"))
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


class LanScanTracker:
    """Spots an app reaching out to many local devices, or many ports on one, in a short time.

    That's what network scanning and worm-like spreading look like. Streaming from a media
    server or browsing a NAS touches one or two devices on a couple of ports, so it never trips.
    Connection attempts to closed ports fail in milliseconds and can slip between samples, so
    this catches slow or wide scans best (dead addresses hang for seconds and are seen).
    """

    def __init__(self, window=120, max_hosts=12, max_ports=20):
        self.window = window
        self.max_hosts = max_hosts
        self.max_ports = max_ports
        self.events: dict[str, list[tuple[float, str, int]]] = defaultdict(list)
        self.seen: set[tuple] = set()

    def observe(self, procs: list[Process], now: float | None = None):
        now = time.time() if now is None else now
        current = set()
        for p in procs:
            for c in p.local:
                current.add(c.key)
                if c.key not in self.seen:
                    self.events[p.exe or p.name].append((now, c.raddr, c.rport))
        self.seen = current
        cutoff = now - self.window
        for app in list(self.events):
            self.events[app] = [e for e in self.events[app] if e[0] >= cutoff]
            if not self.events[app]:
                del self.events[app]

    def check(self, app: str) -> Alert | None:
        events = self.events.get(app, [])
        hosts = {ip for _, ip, _ in events}
        if len(hosts) >= self.max_hosts:
            return Alert(MEDIUM, f"Contacted {len(hosts)} devices on your network within "
                                 f"{self.window // 60} min (possible network scan)", topic="lan-scan")
        ports: dict[str, set[int]] = defaultdict(set)
        for _, ip, port in events:
            ports[ip].add(port)
        ip, used = max(ports.items(), key=lambda kv: len(kv[1]), default=(None, set()))
        if len(used) >= self.max_ports:
            return Alert(MEDIUM, f"Tried {len(used)} ports on {ip} within {self.window // 60} min "
                                 "(possible port scan)", topic="lan-scan")
        return None


def new_domain_alert(domain: str, created: float | None, now: float | None = None) -> Alert | None:
    if not created:
        return None
    days = ((time.time() if now is None else now) - created) / 86400
    if days >= NEW_DOMAIN_DAYS:
        return None
    when = time.strftime("%b %d", time.localtime(created))
    age = "today" if days < 1 else f"{int(days)} day{'s' if int(days) != 1 else ''} ago"
    return Alert(MEDIUM if days < VERY_NEW_DOMAIN_DAYS else LOW,
                 f"{registrable(domain)} was registered {age} ({when})", topic="new-domain")


def unattributed_lookups(dns, blocklist, procs, window: float = 600) -> list[Process]:
    """Known-bad domains looked up recently that no current connection explains.

    resolved doesn't say which app asked, so these show as one "app unknown" entry: the
    lookup alone matters (malware often resolves its C2 before, or without, connecting).
    """
    if not hasattr(blocklist, "domain_hit"):
        return []
    explained = {c.domain for p in procs for c in p.connections if c.domain}
    alerts, seen = [], set()
    for _, domain in dns.lookups_since(time.time() - window):
        if domain in seen or domain in explained:
            continue
        seen.add(domain)
        hit = blocklist.domain_hit(domain)
        if hit:
            alerts.append(Alert(hit.severity, f"Something looked up {domain}: {hit.describe()}", kind="intel",
                                topic="lookup"))
    if not alerts:
        return []
    return [Process(pid=None, name="DNS lookup (app unknown)", alerts=alerts)]


def analyze(procs: list[Process], blocklist: dict | None = None,
            tracker: BeaconTracker | None = None, trust=None, baseline=None, integrity=None,
            dns=None, geo=None, traffic=None, lan_scan: LanScanTracker | None = None,
            ages=None) -> list[Process]:
    """Attach alerts and "new" tags to every process and connection, then sort the worst first."""
    blocklist = {} if blocklist is None else blocklist  # an Intel with only domains is falsy
    for p in procs:
        for c in p.connections:
            if dns:
                c.domain = dns.name_for(c.raddr)
            if geo:
                c.owner = geo.lookup(c.raddr) if c.scope == "internet" else None
    if tracker:
        tracker.observe(procs)
    if traffic:
        traffic.observe(procs)
    if lan_scan:
        lan_scan.observe(procs)
    for p in procs:
        p.alerts = check_process(p)
        if integrity and p.internet:
            tampered = integrity.alert_for(p)
            if tampered:
                p.alerts.append(tampered)
        scan = lan_scan.check(p.exe or p.name) if lan_scan else None
        if scan:
            p.alerts.append(scan)
        sent = traffic.uploaded(p.exe or p.name, UPLOAD_WINDOW) if traffic else 0
        if sent >= UPLOAD_LIMIT:
            p.alerts.append(Alert(LOW, f"Uploaded {human_bytes(sent)} in the last {UPLOAD_WINDOW // 60} min",
                                  topic="upload"))
        for c in p.connections:
            c.alerts = check_connection(c, blocklist)
            if ages and c.domain and c.scope == "internet":
                young = new_domain_alert(c.domain, ages.created(c.domain))
                if young:
                    c.alerts.append(young)
            if tracker and c.scope == "internet":
                every = tracker.interval(p.exe or p.name, c.raddr, c.rport)
                if every:
                    c.alerts.append(Alert(MEDIUM, f"Beaconing: reconnects every ~{every:.0f}s", topic="beacon"))
    if dns:
        procs.extend(unattributed_lookups(dns, blocklist, procs))
    if trust:
        trust.apply(procs)
    if baseline:
        baseline.observe(procs)
    procs.sort(key=lambda p: (-p.severity, -len(p.internet), p.name.lower()))
    return procs
