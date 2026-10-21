"""Snapshot of the system's network sockets, grouped by the process that owns them."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import psutil

LOW, MEDIUM, HIGH = 1, 2, 3
SEVERITY_NAMES = {0: "ok", LOW: "low", MEDIUM: "medium", HIGH: "high"}
SEVERITY_COLORS = {0: "#3fb950", LOW: "#d29922", MEDIUM: "#f0883e", HIGH: "#f85149"}

CGNAT = ipaddress.ip_network("100.64.0.0/10")  # Tailscale and carrier-grade NAT
# The app has already closed these; the kernel is only finishing the TCP teardown, sometimes
# for minutes after the process exited. (CLOSE_WAIT stays: the app still holds that socket.)
CLOSED_STATES = {psutil.CONN_TIME_WAIT, psutil.CONN_FIN_WAIT1, psutil.CONN_FIN_WAIT2,
                 psutil.CONN_CLOSING, psutil.CONN_LAST_ACK, psutil.CONN_CLOSE}


@dataclass
class Alert:
    severity: int
    message: str
    kind: str = ""  # "intel" for threat-intel hits, "never-mute" for signs trust can't explain away
    muted: bool = False  # the user trusts this app or destination
    topic: str = ""  # which explanation in explain.py applies


@dataclass
class Connection:
    pid: int | None
    proto: str
    laddr: str
    lport: int
    raddr: str | None
    rport: int | None
    status: str
    scope: str  # internet, lan, loopback or listening
    alerts: list[Alert] = field(default_factory=list)
    new: bool = False  # first contact with this destination network
    domain: str = ""  # the name the app looked up to get this IP, if DNS was watched
    owner: object = None  # geo.Owner of the remote address, once the database is loaded
    device: str = ""  # the name you gave this local device, if any
    sent: int = 0  # bytes so far (TCP only; the kernel keeps no per-socket count for UDP)
    received: int = 0
    up: float = 0.0  # bytes per second since the last snapshot
    down: float = 0.0

    @property
    def key(self):
        return (self.pid, self.proto, self.lport, self.raddr, self.rport)

    @property
    def local(self):
        return _endpoint(self.laddr, self.lport)

    @property
    def remote(self):
        return _endpoint(self.raddr, self.rport) if self.raddr else ""

    @property
    def local_device(self) -> bool:
        """A connection to another device on your network (not multicast/broadcast chatter)."""
        return self.scope == "lan" and bool(self.raddr) and is_device(self.raddr)


@dataclass
class Process:
    pid: int | None
    name: str
    exe: str = ""
    exe_deleted: bool = False
    cmdline: str = ""
    user: str = ""
    connections: list[Connection] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    new: bool = False  # first time this app reached the internet

    @property
    def internet(self):
        return [c for c in self.connections if c.scope == "internet"]

    @property
    def local(self):
        return [c for c in self.connections if c.local_device]

    def all_alerts(self):
        return self.alerts + [a for c in self.connections for a in c.alerts]

    @property
    def severity(self):
        return max((a.severity for a in self.all_alerts() if not a.muted), default=0)

    @property
    def has_new(self):
        return self.new or any(c.new for c in self.connections)

    @property
    def up(self):
        return sum(c.up for c in self.connections)

    @property
    def down(self):
        return sum(c.down for c in self.connections)


def severity_of(alerts) -> int:
    return max((a.severity for a in alerts if not a.muted), default=0)


def _endpoint(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def normalize_ip(ip: str) -> str:
    """Strip IPv4-mapped IPv6 prefixes and zone ids so addresses compare cleanly."""
    ip = ip.split("%")[0]
    if ip.startswith("::ffff:") and "." in ip:
        return ip[7:]
    return ip


def classify_ip(ip: str) -> str:
    addr = ipaddress.ip_address(normalize_ip(ip))
    if addr.is_loopback:
        return "loopback"
    if (addr.is_private or addr.is_link_local or addr.is_multicast
            or addr.is_unspecified or addr.is_reserved or addr in CGNAT):
        return "lan"
    return "internet"


def is_device(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (addr.is_multicast or addr.is_unspecified or addr.is_loopback or ip.endswith(".255"))


def local_kind(ip: str) -> str:
    """How to describe a non-internet address in the Network column."""
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return "This computer"
    if addr in CGNAT:
        return "🔒 Tailscale / CGNAT"
    if addr.is_multicast or ip.endswith(".255"):
        return "Broadcast / discovery"
    if addr.is_link_local:
        return "🏠 Local network (link-local)"
    return "🏠 Local network"


VIEWS = ("internet", "local", "all")


def visible_connections(proc: Process, view: str | bool) -> list[Connection]:
    """Connections for one view: "internet" (plus anything flagged), "local" (devices on your
    network, plus anything flagged) or "all" (also loopback, listening and broadcast)."""
    if view is True or view == "all":
        return proc.connections
    if view == "local":
        return [c for c in proc.connections if c.local_device or c.alerts]
    return [c for c in proc.connections if c.scope == "internet" or c.alerts]


def arp_table() -> dict[str, str]:
    """IP -> MAC address of devices this computer has talked to on the local network."""
    table = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                fields = line.split()
                if len(fields) >= 4 and fields[3] != "00:00:00:00:00:00":
                    table[fields[0]] = fields[3].lower()
    except (OSError, StopIteration):
        pass
    return table


def _proc_info(pid: int | None) -> Process:
    if pid is None:
        return Process(pid=None, name="(owned by another user; run as root to identify)")
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            name = p.name()
            exe = _try(p.exe)
            cmdline = " ".join(_try(p.cmdline, []))
            user = _try(p.username)
    except psutil.NoSuchProcess:
        return Process(pid=pid, name="(exited)")
    except psutil.AccessDenied:
        return Process(pid=pid, name=f"pid {pid}")
    try:
        deleted = os.readlink(f"/proc/{pid}/exe").endswith(" (deleted)")
    except OSError:
        deleted = False
    return Process(pid, name, exe, deleted, cmdline, user)


def _try(fn, default=""):
    try:
        return fn()
    except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess):
        return default


def snapshot() -> list[Process]:
    # Ask each process for its own sockets: the system-wide call reports only one owner per
    # socket, which hides e.g. a reverse shell whose socket is inherited by its children.
    procs: dict[int | None, Process] = {}
    seen = set()
    for p in psutil.process_iter():
        try:
            conns = p.net_connections(kind="inet")
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        for c in conns:
            _add(procs, p.pid, c)
            seen.add((c.laddr, c.raddr, c.type))
    # Whatever is left belongs to processes we may not inspect (other users, without root).
    for c in psutil.net_connections(kind="inet"):
        if (c.laddr, c.raddr, c.type) not in seen:
            _add(procs, None, c)
    return list(procs.values())


def _add(procs, pid, c):
    if c.status in CLOSED_STATES:
        return
    proc = procs.get(pid)
    if proc is None:
        proc = procs[pid] = _proc_info(pid)
    raddr = normalize_ip(c.raddr.ip) if c.raddr else None
    proc.connections.append(Connection(
        pid=pid,
        proto="tcp" if c.type == socket.SOCK_STREAM else "udp",
        laddr=normalize_ip(c.laddr.ip),
        lport=c.laddr.port,
        raddr=raddr,
        rport=c.raddr.port if c.raddr else None,
        status="" if c.status == psutil.CONN_NONE else c.status,
        scope=classify_ip(raddr) if raddr else "listening",
    ))


def tcp_counters() -> dict[tuple, tuple[int, int]]:
    """(laddr, lport, raddr, rport) -> (bytes sent and acknowledged, bytes received), from ss."""
    try:
        out = subprocess.run(["ss", "-tinHO"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    counters = {}
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        local, peer = _split_endpoint(fields[3]), _split_endpoint(fields[4])
        sent = re.search(r"\bbytes_acked:(\d+)", line)
        received = re.search(r"\bbytes_received:(\d+)", line)
        if local and peer and (sent or received):
            counters[local + peer] = (int(sent.group(1)) if sent else 0, int(received.group(1)) if received else 0)
    return counters


def _split_endpoint(text: str):
    host, _, port = text.rpartition(":")
    if not port.isdigit():
        return None
    return normalize_ip(host.strip("[]")), int(port)


class Traffic:
    """Turns the kernel's running byte counts into per-connection rates.

    Connections already open when monitoring starts begin at their current count, so their
    history isn't mistaken for a burst. `uploaded(app, window)` sums what an app sent recently.
    """

    def __init__(self):
        self.last: dict[tuple, tuple[int, int]] = {}
        self.last_time: float | None = None
        self.sent_log: dict[str, deque] = {}  # app -> (time, bytes) uploads, for the big-upload check

    def observe(self, procs: list[Process], now: float | None = None, counters=None):
        now = time.time() if now is None else now
        counters = tcp_counters() if counters is None else counters
        first = self.last_time is None
        elapsed = max(now - (self.last_time or now), 1e-6)
        current = {}
        for p in procs:
            app = p.exe or p.name
            for c in p.connections:
                if c.proto != "tcp" or not c.raddr:
                    continue
                key = (c.laddr, c.lport, c.raddr, c.rport)
                if key not in counters:
                    continue
                c.sent, c.received = counters[key]
                current[key] = (c.sent, c.received)
                if key in self.last:
                    before = self.last[key]
                elif first:
                    continue
                else:
                    before = (0, 0)  # opened since the last look: everything it moved is recent
                delta_up = max(0, c.sent - before[0])
                c.up = delta_up / elapsed
                c.down = max(0, c.received - before[1]) / elapsed
                if delta_up and c.scope == "internet":
                    self.sent_log.setdefault(app, deque()).append((now, delta_up))
        self.last, self.last_time = current, now

    def uploaded(self, app: str, window: float = 600, now: float | None = None) -> int:
        now = time.time() if now is None else now
        log = self.sent_log.get(app)
        if not log:
            return 0
        while log and log[0][0] < now - window:
            log.popleft()
        return sum(n for _, n in log)


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" or n >= 100 else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def rate_text(up: float, down: float) -> str:
    """'↑ 1.2 KB/s ↓ 40 KB/s', or '' when idle."""
    if up < 1 and down < 1:
        return ""
    return f"↑ {human_bytes(up)}/s  ↓ {human_bytes(down)}/s"


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


class Resolver:
    """Non-blocking reverse DNS: returns what is cached and looks up the rest in the background."""

    def __init__(self, workers: int = 8):
        self.cache: dict[str, str] = {}
        self.pool = ThreadPoolExecutor(workers)

    def get(self, ip: str) -> str:
        if ip not in self.cache:
            self.cache[ip] = ""
            self.pool.submit(self._lookup, ip)
        return self.cache[ip]

    def _lookup(self, ip):
        self.cache[ip] = reverse_dns(ip)
