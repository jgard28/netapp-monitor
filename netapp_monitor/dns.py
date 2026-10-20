"""Watches DNS lookups through systemd-resolved, so connections can be tied to domain names.

resolved publishes every answered query on a varlink socket. Subscribing needs a polkit
permission that install-system.sh grants to your user. Apps that resolve names on their
own (DNS-over-HTTPS in a browser, hard-coded IPs) bypass this and fall back to reverse DNS.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
import socket
import threading
import time
from collections import Counter, OrderedDict, deque

MONITOR_SOCKET = "/run/systemd/resolve/io.systemd.Resolve.Monitor"
SUBSCRIBE = {"method": "io.systemd.Resolve.Monitor.SubscribeQueryResults", "parameters": {}, "more": True}
TYPE_A, TYPE_CNAME, TYPE_AAAA = 1, 5, 28


def parse_result(params: dict) -> list[tuple[str, str]]:
    """(ip, domain) pairs from one SubscribeQueryResults reply.

    The domain is what the app asked for; CNAME hops in between are skipped, so a lookup
    of www.example.com that lands on a CDN still reads as www.example.com.
    """
    if params.get("state") not in (None, "success"):
        return []
    question = (params.get("question") or [{}])[0].get("name", "").rstrip(".").lower()
    pairs = []
    for answer in params.get("answer") or []:
        rr = answer.get("rr") or {}
        rtype = (rr.get("key") or {}).get("type")
        address = rr.get("address")
        if rtype in (TYPE_A, TYPE_AAAA) and isinstance(address, list):
            try:
                ip = str(ipaddress.ip_address(bytes(address)))
            except ValueError:
                continue
            name = question or (rr.get("key") or {}).get("name", "").rstrip(".").lower()
            if name:
                pairs.append((ip, name))
    return pairs


class DnsWatcher:
    """Background subscriber that remembers which domain each IP was looked up as."""

    def __init__(self, max_entries: int = 50000):
        self.names: OrderedDict[str, str] = OrderedDict()  # ip -> domain, most recent last
        self.recent: deque[tuple[float, str]] = deque(maxlen=2000)  # (time, domain) lookups
        self.max_entries = max_entries
        self.status = "starting"  # starting, watching, needs-setup, unavailable
        self.lock = threading.Lock()
        threading.Thread(target=self._run, daemon=True).start()

    def name_for(self, ip: str | None) -> str:
        if not ip:
            return ""
        with self.lock:
            return self.names.get(ip, "")

    def lookups_since(self, since: float) -> list[tuple[float, str]]:
        with self.lock:
            return [(t, d) for t, d in self.recent if t >= since]

    def record(self, pairs, now=None):
        now = time.time() if now is None else now
        with self.lock:
            for ip, name in pairs:
                self.names[ip] = name
                self.names.move_to_end(ip)
            for name in {n for _, n in pairs}:
                self.recent.append((now, name))
            while len(self.names) > self.max_entries:
                self.names.popitem(last=False)

    def _run(self):
        while True:
            try:
                self._subscribe()
            except PermissionError:
                self.status = "needs-setup"
            except OSError:
                self.status = "unavailable"
            time.sleep(30)

    def _subscribe(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(MONITOR_SOCKET)
            s.sendall(json.dumps(SUBSCRIBE).encode() + b"\0")
            buf = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    raise OSError("resolved closed the monitor connection")
                buf += chunk
                while b"\0" in buf:
                    raw, buf = buf.split(b"\0", 1)
                    msg = json.loads(raw)
                    if "error" in msg:
                        if "Authentication" in msg["error"] or "PermissionDenied" in msg["error"]:
                            raise PermissionError(msg["error"])
                        raise OSError(msg["error"])
                    self.status = "watching"
                    self.record(parse_result(msg.get("parameters") or {}))


# --- domain heuristics ------------------------------------------------------------

# Second-level suffixes where the registrable name is one label further left.
MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz",
                  "com.br", "com.cn", "com.sg", "com.mx", "co.in", "co.za", "com.tr", "com.tw", "co.kr"}


def registrable(domain: str) -> str:
    labels = domain.rstrip(".").lower().split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES else 2
    return ".".join(labels[-n:])


def parents(domain: str):
    """example.com's lookups also match listings for its parent domains, up to the registrable one."""
    labels = domain.rstrip(".").lower().split(".")
    stop = len(registrable(domain).split("."))
    for i in range(0, len(labels) - stop + 1):
        yield ".".join(labels[i:])


def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def looks_generated(domain: str) -> bool:
    """True for names like 'xjwqkzpmrtvb.com' that domain-generation malware produces.

    Only the registrable label is judged (CDNs put random IDs in subdomains, which is fine).
    """
    label = registrable(domain).split(".")[0]
    if len(label) < 10 or label.startswith("xn--") or "-" in label or domain.endswith(".onion"):
        return False
    vowel_ratio = sum(ch in "aeiouy" for ch in label) / len(label)
    digit_ratio = sum(ch.isdigit() for ch in label) / len(label)
    consonant_run = max((len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxz]+", label)), default=0)
    # Real words can have 5-consonant runs ("bismarckchiro..."), so that alone isn't enough.
    odd = (digit_ratio >= 0.3 or vowel_ratio < 0.2 or consonant_run >= 7
           or (consonant_run >= 5 and vowel_ratio < 0.22))
    return odd and entropy(label) >= 3.2
