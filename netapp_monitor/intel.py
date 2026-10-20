"""Free threat-intel IP blocklists, cached locally and refreshed every few hours."""
from __future__ import annotations

import ipaddress
import os
import sys
import time
import urllib.request
from pathlib import Path

FEEDS = [
    ("feodo", "abuse.ch Feodo Tracker: botnet C2",
     "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("ipsum3", "IPsum: listed on 3+ blocklists",
     "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"),
]
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "netapp-monitor"
# Your own IOCs, one IP per line; '#' starts a comment. Picked up live by the tray app.
USER_LIST = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "netapp-monitor" / "blocklist.txt"
MAX_AGE = 12 * 3600


def user_list_mtime() -> float:
    try:
        return USER_LIST.stat().st_mtime
    except OSError:
        return 0.0


def parse(text: str):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        yield token


def _download(url: str, path: Path):
    req = urllib.request.Request(url, headers={"User-Agent": "netapp-monitor"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = resp.read()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def load(update: bool = True) -> dict[str, str]:
    """Map of blocklisted IP to the feed that listed it. Falls back to the cache when offline."""
    blocklist: dict[str, str] = {}
    if USER_LIST.exists():
        for ip in parse(USER_LIST.read_text(errors="replace")):
            blocklist[ip] = "your blocklist"
    for feed_id, label, url in FEEDS:
        path = CACHE_DIR / f"{feed_id}.txt"
        stale = not path.exists() or time.time() - path.stat().st_mtime > MAX_AGE
        if update and stale:
            try:
                _download(url, path)
            except OSError as e:
                print(f"netapp-monitor: could not update {label}: {e}", file=sys.stderr)
        if path.exists():
            for ip in parse(path.read_text(errors="replace")):
                blocklist.setdefault(ip, label)
    return blocklist
