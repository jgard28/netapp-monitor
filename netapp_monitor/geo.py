"""Who runs the network an IP belongs to, and in which country, from an offline database.

Uses iptoasn.com's public-domain IP-to-ASN table (about 9 MB, refreshed weekly). Lookups
happen locally, so no IP you connect to is ever sent anywhere.
"""
from __future__ import annotations

import array
import bisect
import gzip
import os
import re
import socket
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass

from .intel import CACHE_DIR

URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
PATH = CACHE_DIR / "ip2asn-combined.tsv.gz"
MAX_AGE = 7 * 86400

# Well-known networks under the names people recognize.
NAMES = {
    13335: "Cloudflare", 16509: "Amazon AWS", 14618: "Amazon AWS", 8987: "Amazon", 15169: "Google",
    396982: "Google Cloud", 19527: "Google", 8075: "Microsoft", 8068: "Microsoft", 32934: "Meta",
    54113: "Fastly", 20940: "Akamai", 16625: "Akamai", 714: "Apple", 6185: "Apple", 36459: "GitHub",
    2906: "Netflix", 46489: "Twitch", 13414: "Twitter/X", 36040: "YouTube", 47764: "Mail.ru",
    24940: "Hetzner", 213230: "Hetzner", 212317: "Hetzner", 16276: "OVH", 14061: "DigitalOcean",
    63949: "Linode (Akamai)", 20473: "Vultr", 51167: "Contabo", 9009: "M247", 60781: "Leaseweb",
    28753: "Leaseweb", 30633: "Leaseweb", 47583: "Hostinger", 212238: "Datacamp", 8560: "IONOS",
    12876: "Scaleway", 36352: "ColoCrossing", 53667: "FranTech (BuyVM)", 202425: "IP Volume",
    44477: "Stark Industries", 40676: "Psychz", 8100: "QuadraNet", 49505: "Selectel", 9123: "Timeweb",
    54290: "Hostwinds", 29802: "HIVELOCITY", 41231: "Canonical", 7922: "Comcast", 7018: "AT&T",
    701: "Verizon", 3320: "Deutsche Telekom",
}
# Cheap rented servers (VPS / dedicated hosting). Plenty of honest sites live here, but so does
# most malware infrastructure: attackers rent the same machines anyone can.
HOSTING_ASNS = {
    24940, 213230, 212317, 16276, 14061, 63949, 20473, 51167, 9009, 60781, 28753, 30633, 47583,
    212238, 8560, 12876, 36352, 53667, 202425, 44477, 40676, 8100, 49505, 9123, 54290, 29802,
}
HOSTING_WORDS = re.compile(r"host|vps|server|datacent|data cent|colo|dedi", re.I)
FLAG_BASE = 0x1F1E6 - ord("A")


@dataclass(frozen=True)
class Owner:
    asn: int
    country: str  # ISO code, or "" when unknown
    org: str
    hosting: bool  # a rented-server provider

    @property
    def flag(self) -> str:
        if len(self.country) != 2 or not self.country.isalpha():
            return ""
        return "".join(chr(FLAG_BASE + ord(ch)) for ch in self.country.upper())

    def label(self) -> str:
        """'🇩🇪 DE · Hetzner (rented server)'"""
        place = f"{self.flag} {self.country}".strip()
        text = " · ".join(filter(None, [place, self.org]))
        return text + (" (rented server)" if self.hosting else "")


def tidy_org(asn: int, desc: str) -> str:
    """'GTELECOM-AS-AP Gtelecom Pty Ltd' -> 'Gtelecom Pty Ltd', 'HETZNER-AS' -> 'Hetzner'."""
    if asn in NAMES:
        return NAMES[asn]
    head, _, rest = desc.partition(" ")
    rest = rest.strip(" ,-")
    if rest and any(ch.islower() for ch in rest) and re.fullmatch(r"[A-Z0-9][A-Z0-9_.-]*", head):
        return rest
    if any(ch.islower() for ch in desc):
        return desc
    if rest:
        return desc.title()
    name = re.sub(r"(-(AS|ASN|AP|NET|NETWORK|BGP)(-[A-Z0-9]+)?)+$", "", head, flags=re.I) or head
    return name.replace("-", " ").title() if name.isupper() else name


def _ip_int(ip: str) -> tuple[int, int]:
    """(version, integer) for an address string."""
    if ":" in ip:
        return 6, int.from_bytes(socket.inet_pton(socket.AF_INET6, ip), "big")
    return 4, int.from_bytes(socket.inet_aton(ip), "big")


class GeoDB:
    """Sorted IP ranges with their owner; loads (and refreshes) in the background."""

    def __init__(self, path=PATH, update: bool = True, background: bool = True):
        self.path = path
        self.ready = False
        self.v4_start, self.v4_end, self.v4_owner = array.array("I"), array.array("I"), array.array("I")
        self.v6_start: list[int] = []
        self.v6_end: list[int] = []
        self.v6_owner = array.array("I")
        self.owners: list[Owner] = []
        self.cache: dict[str, Owner | None] = {}
        if background:
            threading.Thread(target=self.load, args=(update,), daemon=True).start()
        else:
            self.load(update)

    def load(self, update: bool = True):
        stale = not os.path.exists(self.path) or time.time() - os.path.getmtime(self.path) > MAX_AGE
        if update and stale:
            try:
                req = urllib.request.Request(URL, headers={"User-Agent": "netapp-monitor"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read()
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                tmp = f"{self.path}.tmp"
                with open(tmp, "wb") as f:
                    f.write(data)
                os.replace(tmp, self.path)
            except OSError as e:
                print(f"netapp-monitor: could not update the IP owner database: {e}", file=sys.stderr)
        if not os.path.exists(self.path):
            return
        try:
            with gzip.open(self.path, "rt", encoding="utf-8", errors="replace") as f:
                self.parse(f)
        except (OSError, EOFError, ValueError) as e:
            print(f"netapp-monitor: could not read the IP owner database: {e}", file=sys.stderr)

    def parse(self, lines):
        v4s, v4e, v4o = array.array("I"), array.array("I"), array.array("I")
        v6s, v6e, v6o = [], [], array.array("I")
        owners: list[Owner] = []
        index: dict[tuple, int] = {}
        for line in lines:
            parts = line.rstrip("\n").split("\t", 4)
            if len(parts) < 5 or parts[2] in ("0", ""):
                continue  # "Not routed"
            start, end, asn, country, desc = parts
            key = (asn, country, desc)
            i = index.get(key)
            if i is None:
                n = int(asn)
                i = index[key] = len(owners)
                owners.append(Owner(n, "" if country in ("None", "ZZ") else country, tidy_org(n, desc),
                                    n in HOSTING_ASNS or bool(HOSTING_WORDS.search(desc))))
            try:
                version, lo = _ip_int(start)
                _, hi = _ip_int(end)
            except OSError:
                continue
            if version == 4:
                v4s.append(lo), v4e.append(hi), v4o.append(i)
            else:
                v6s.append(lo), v6e.append(hi), v6o.append(i)
        # The published file is sorted; anything else is sorted here so the binary search works.
        if any(a > b for a, b in zip(v4s, v4s[1:])):
            rows = sorted(zip(v4s, v4e, v4o))
            v4s, v4e, v4o = (array.array("I", col) for col in zip(*rows))
        if any(a > b for a, b in zip(v6s, v6s[1:])):
            starts, ends, idx = zip(*sorted(zip(v6s, v6e, v6o)))
            v6s, v6e, v6o = list(starts), list(ends), array.array("I", idx)
        self.v4_start, self.v4_end, self.v4_owner = v4s, v4e, v4o
        self.v6_start, self.v6_end, self.v6_owner = v6s, v6e, v6o
        self.owners = owners
        self.cache.clear()
        self.ready = True

    def lookup(self, ip: str | None) -> Owner | None:
        if not ip or not self.ready:
            return None
        if ip in self.cache:
            return self.cache[ip]
        try:
            version, n = _ip_int(ip)
        except OSError:
            return None
        starts, ends, owner = ((self.v4_start, self.v4_end, self.v4_owner) if version == 4
                               else (self.v6_start, self.v6_end, self.v6_owner))
        i = bisect.bisect_right(starts, n) - 1
        found = self.owners[owner[i]] if i >= 0 and n <= ends[i] else None
        if len(self.cache) > 20000:
            self.cache.clear()
        self.cache[ip] = found
        return found
