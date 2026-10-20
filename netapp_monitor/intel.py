"""Free threat-intel feeds, cached locally and refreshed on a schedule.

Each listed IP maps to a Hit saying who listed it, what for, and how much to trust it:
confirmed C2 sources (ThreatFox, Feodo Tracker, your own list) are high severity, while
reputation lists (IPsum: mostly scanners and brute-forcers) are medium.
"""
from __future__ import annotations

import csv
import ipaddress
import os
import re
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .collector import HIGH, MEDIUM
from .dns import parents

CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "netapp-monitor"
# Your own IOCs, one IP per line; text after '#' is shown as the reason. Picked up live.
USER_LIST = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "netapp-monitor" / "blocklist.txt"


@dataclass
class Hit:
    source: str
    severity: int
    detail: str
    ports: set[int] = field(default_factory=set)
    first_seen: str = ""
    confidence: int | None = None

    def describe(self, port: int | None = None) -> str:
        extra = []
        if self.ports and port in self.ports:
            extra.append(f"port {port} matches")
        elif self.ports:
            extra.append(f"listed on port {', '.join(map(str, sorted(self.ports)[:3]))}")
        if self.first_seen:
            extra.append(f"first seen {self.first_seen}")
        if self.confidence is not None:
            extra.append(f"confidence {self.confidence}%")
        return f"{self.source}: {self.detail}" + (f" ({', '.join(extra)})" if extra else "")


def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def parse(text: str):
    """IPs from a plain list: one per line, '#' comments, extra columns ignored."""
    for ip, _rest in parse_columns(text):
        yield ip


def parse_columns(text: str):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        token, *rest = line.split()
        if _is_ip(token):
            yield token, rest


def parse_threatfox(text: str) -> dict[str, Hit]:
    """ThreatFox 'recent ip-port' CSV export."""
    hits: dict[str, Hit] = {}
    rows = csv.reader((l for l in text.splitlines() if l and not l.startswith("#")), skipinitialspace=True)
    for row in rows:
        if len(row) < 10 or row[3] != "ip:port":
            continue
        ip, _, port = row[2].rpartition(":")
        ip = ip.strip("[]")
        if not _is_ip(ip):
            continue
        malware = row[7] if row[7] not in ("", "None") else "unknown malware"
        what = f"{malware} C2 server" if row[4] == "botnet_cc" else f"{malware} {row[4].replace('_', ' ')}"
        hit = hits.get(ip)
        if hit is None:
            hit = hits[ip] = Hit("ThreatFox", HIGH, what, first_seen=row[0][:10],
                                 confidence=int(row[9]) if row[9].isdigit() else None)
        if port.isdigit():
            hit.ports.add(int(port))
    return hits


def parse_feodo(text: str) -> dict[str, Hit]:
    return {ip: Hit("Feodo Tracker", HIGH, "botnet C2 server") for ip in parse(text)}


def parse_ipsum(text: str) -> dict[str, Hit]:
    hits = {}
    for ip, rest in parse_columns(text):
        count = rest[0] if rest and rest[0].isdigit() else "3+"
        hits[ip] = Hit("IPsum", MEDIUM, f"bad reputation, on {count} public blocklists")
    return hits


DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{1,62}$")


def parse_hostfile(text: str) -> dict[str, Hit]:
    """ThreatFox host file: '127.0.0.1<TAB>malicious.domain' per line."""
    hits = {}
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and DOMAIN.match(parts[1].lower()):
            hits[parts[1].lower()] = Hit("ThreatFox", HIGH, "known malware / C2 domain")
    return hits


def parse_user(text: str) -> tuple[dict[str, Hit], dict[str, Hit]]:
    """Your list holds IPs and domains, one per line; text after '#' is the reason."""
    ips, domains = {}, {}
    for line in text.splitlines():
        body, _, comment = line.partition("#")
        token = body.strip().split()[0].lower() if body.strip() else ""
        hit = Hit("Your blocklist", HIGH, comment.strip() or "listed by you")
        if _is_ip(token):
            ips[token] = hit
        elif DOMAIN.match(token):
            domains[token] = hit
    return ips, domains


# (id, name, url, max cache age in seconds, parser, "ips" or "domains"), strongest sources first.
FEEDS = [
    ("threatfox", "ThreatFox", "https://threatfox.abuse.ch/export/csv/ip-port/recent/", 2 * 3600, parse_threatfox, "ips"),
    ("threatfox-domains", "ThreatFox", "https://threatfox.abuse.ch/downloads/hostfile/", 2 * 3600, parse_hostfile, "domains"),
    ("feodo", "Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", 12 * 3600, parse_feodo, "ips"),
    ("ipsum3", "IPsum", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", 12 * 3600, parse_ipsum, "ips"),
]


def user_list_mtime() -> float:
    try:
        return USER_LIST.stat().st_mtime
    except OSError:
        return 0.0


def _download(url: str, path: Path):
    req = urllib.request.Request(url, headers={"User-Agent": "netapp-monitor"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


class Intel(dict):
    """IP -> Hit, plus listed domains and how many entries each source contributed."""

    def __init__(self):
        super().__init__()
        self.domains: dict[str, Hit] = {}
        self.counts: dict[str, int] = {}

    def merge(self, source: str, hits: dict[str, Hit], domains: bool = False):
        self.counts[source] = self.counts.get(source, 0) + len(hits)
        table = self.domains if domains else self
        for key, hit in hits.items():
            current = table.get(key)
            if current is None or hit.severity > current.severity:
                table[key] = hit

    def domain_hit(self, domain: str) -> Hit | None:
        """Listed domain, or a listed parent of it (a.evil.com matches evil.com)."""
        if not domain:
            return None
        for candidate in parents(domain):
            if candidate in self.domains:
                return self.domains[candidate]
        return None

    def summary(self) -> str:
        short = {"Feodo Tracker": "Feodo", "Your blocklist": "yours"}
        return " · ".join(f"{short.get(s, s)} {n:,}" for s, n in self.counts.items())


def load(update: bool = True) -> Intel:
    """Load every feed, refreshing stale caches first unless offline."""
    intel = Intel()
    user_ips, user_domains = parse_user(USER_LIST.read_text(errors="replace")) if USER_LIST.exists() else ({}, {})
    intel.merge("Your blocklist", user_ips)
    intel.merge("Your blocklist", user_domains, domains=True)
    for feed_id, name, url, max_age, parser, kind in FEEDS:
        path = CACHE_DIR / f"{feed_id}.txt"
        stale = not path.exists() or time.time() - path.stat().st_mtime > max_age
        if update and stale:
            try:
                _download(url, path)
            except OSError as e:
                print(f"netapp-monitor: could not update {name}: {e}", file=sys.stderr)
        if path.exists():
            intel.merge(name, parser(path.read_text(errors="replace")), domains=kind == "domains")
    return intel
