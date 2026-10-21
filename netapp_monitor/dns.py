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

# Public DNS-over-HTTPS services. An app talking HTTPS to one of these resolves names itself,
# so its lookups never reach the system resolver (Firefox and Chrome do this by default in
# some regions). That's a legitimate privacy choice, not an alert.
DOH_HOSTS = ("cloudflare-dns.com", "dns.google", "dns.quad9.net", "dns.nextdns.io", "doh.mullvad.net",
             "dns.adguard-dns.com", "doh.opendns.com", "doh.cleanbrowsing.org", "dns.controld.com")
DOH_IPS = {
    "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",  # Cloudflare
    "162.159.61.4", "172.64.41.4", "2803:f800:53::4", "2a06:98c1:52::4",  # Firefox's Cloudflare
    "162.159.61.3", "172.64.41.3", "2803:f800:53::3", "2a06:98c1:52::3",  # Chrome's Cloudflare
    "104.16.248.249", "104.16.249.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9",
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",  # Google
    "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",  # Quad9
    "94.140.14.14", "94.140.15.15", "194.242.2.2", "208.67.222.222", "208.67.220.220",
}


def parse_result(params: dict) -> list[tuple[str, str]]:
    """(ip, domain) pairs from one SubscribeQueryResults reply.

    The domain is what the app asked for; CNAME hops in between are skipped, so a lookup
    of www.example.com that lands on a CDN still reads as www.example.com.
    """
    if params.get("state") not in (None, "success"):
        return []
    # When resolved follows a CNAME it re-asks for the target and lists the original question
    # under "collectedQuestions"; the original is the name the app actually looked up.
    asked = params.get("collectedQuestions") or params.get("question") or [{}]
    question = asked[0].get("name", "").rstrip(".").lower()
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
        self.watching_since: float | None = None
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
                    if self.status != "watching":
                        self.status, self.watching_since = "watching", time.time()
                    self.record(parse_result(msg.get("parameters") or {}))


def is_doh(conn) -> bool:
    """True for an HTTPS connection to a public DNS-over-HTTPS service."""
    if conn.rport != 443:
        return False
    return conn.raddr in DOH_IPS or any(conn.domain == h or conn.domain.endswith("." + h) for h in DOH_HOSTS)


def own_dns(proc, first_seen: dict, watching_since: float | None, now: float | None = None) -> bool:
    """Whether the app resolves names itself (DNS-over-HTTPS), so its domains can't be seen.

    Certain when it talks to a known DoH service; otherwise inferred when at least 3 of its
    connections opened while lookups were being watched and none matched a lookup.
    """
    if watching_since is None or not proc.internet:
        return False
    if any(is_doh(c) for c in proc.internet):
        return True
    now = time.time() if now is None else now
    fresh = [c for c in proc.internet if first_seen.get(c.key, 0) > watching_since + 5 and now - first_seen[c.key] > 3]
    return len(fresh) >= 3 and not any(c.domain for c in fresh)


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
