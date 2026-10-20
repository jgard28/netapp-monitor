"""Snapshot of the system's network sockets, grouped by the process that owns them."""
from __future__ import annotations

import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import psutil

LOW, MEDIUM, HIGH = 1, 2, 3
SEVERITY_NAMES = {0: "ok", LOW: "low", MEDIUM: "medium", HIGH: "high"}

CGNAT = ipaddress.ip_network("100.64.0.0/10")  # Tailscale and carrier-grade NAT
# The app has already closed these; the kernel is only finishing the TCP teardown, sometimes
# for minutes after the process exited. (CLOSE_WAIT stays: the app still holds that socket.)
CLOSED_STATES = {psutil.CONN_TIME_WAIT, psutil.CONN_FIN_WAIT1, psutil.CONN_FIN_WAIT2,
                 psutil.CONN_CLOSING, psutil.CONN_LAST_ACK, psutil.CONN_CLOSE}


@dataclass
class Alert:
    severity: int
    message: str


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

    @property
    def key(self):
        return (self.pid, self.proto, self.lport, self.raddr, self.rport)

    @property
    def local(self):
        return _endpoint(self.laddr, self.lport)

    @property
    def remote(self):
        return _endpoint(self.raddr, self.rport) if self.raddr else ""


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

    @property
    def internet(self):
        return [c for c in self.connections if c.scope == "internet"]

    def all_alerts(self):
        return self.alerts + [a for c in self.connections for a in c.alerts]

    @property
    def severity(self):
        return max((a.severity for a in self.all_alerts()), default=0)


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


def visible_connections(proc: Process, show_all: bool) -> list[Connection]:
    """Internet connections plus anything flagged, or everything when show_all is set."""
    if show_all:
        return proc.connections
    return [c for c in proc.connections if c.scope == "internet" or c.alerts]


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
