"""How old a domain is, from its registry's public RDAP record (the modern WHOIS).

Malware and phishing domains are usually days or weeks old when they're used; real services
have typically existed for years. Only the registered domain (e.g. "example.com", never the
full name or anything else about the connection) is sent, straight to the registry for that
TLD as listed by IANA. Answers are cached, so each domain is asked about once. Some TLDs
(.io, .de and other country domains) publish no RDAP data; those are simply skipped.
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

from .dns import registrable
from .intel import CACHE_DIR, DOMAIN

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP = CACHE_DIR / "rdap-bootstrap.json"
CACHE = CACHE_DIR / "domain-ages.json"
BOOTSTRAP_MAX_AGE = 7 * 86400
RECHECK_UNKNOWN = 7 * 86400  # retry domains the registry had no date for
RECHECK_KNOWN = 30 * 86400  # a domain can lapse and be re-registered by someone else
RETRY_FAILED = 15 * 60  # after a network error (offline, registry down)
MIN_GAP = 1.0  # seconds between requests, to be polite to registries
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".localdomain", ".home.arpa", ".arpa", ".onion")


def registration_date(rdap: dict) -> float | None:
    for event in rdap.get("events") or []:
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            try:
                return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00")).timestamp()
            except ValueError:
                return None
    return None


def servers_from_bootstrap(data: dict) -> dict[str, str]:
    """TLD -> RDAP base URL (https preferred)."""
    servers = {}
    for tlds, urls in data.get("services", []):
        url = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
        for tld in tlds:
            if url:
                servers[tld.lower()] = url if url.endswith("/") else url + "/"
    return servers


class DomainAges:
    """Background RDAP lookups with a persistent cache; `created(domain)` never blocks."""

    def __init__(self, enabled: bool = True, cache_path=CACHE, bootstrap_path=BOOTSTRAP, start: bool = True):
        self.enabled = enabled
        self.cache_path = cache_path
        self.bootstrap_path = bootstrap_path
        self.lock = threading.Lock()
        self.ages: dict[str, dict] = self._load()
        self.queued: set[str] = set()
        self.failed: dict[str, float] = {}  # name -> when a lookup last failed
        self.jobs: queue.Queue[str] = queue.Queue()
        self.servers: dict[str, str] | None = None
        self.dirty = False
        if start:
            threading.Thread(target=self._run, daemon=True).start()

    def _load(self) -> dict:
        try:
            with open(self.cache_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def save(self):
        with self.lock:
            if not self.dirty:
                return
            data = dict(self.ages)
            self.dirty = False
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        tmp = f"{self.cache_path}.tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.cache_path)

    def created(self, domain: str, now: float | None = None) -> float | None:
        """Registration time of the domain's registered name, if known; queues a lookup if not."""
        if not domain or not self.enabled:
            return None
        name = registrable(domain)
        if "." not in name or name.endswith(LOCAL_SUFFIXES) or not DOMAIN.match(name):
            return None
        now = time.time() if now is None else now
        with self.lock:
            entry = self.ages.get(name)
            stale = entry is None or now - entry["checked"] > (RECHECK_KNOWN if entry.get("created")
                                                               else RECHECK_UNKNOWN)
            retry_ok = now - self.failed.get(name, 0) > RETRY_FAILED
            if stale and retry_ok and name not in self.queued:
                self.queued.add(name)
                self.jobs.put(name)
        return entry.get("created") if entry else None

    def record(self, name: str, created: float | None, now: float | None = None):
        with self.lock:
            self.ages[name] = {"created": created, "checked": time.time() if now is None else now}
            self.queued.discard(name)
            self.dirty = True

    # --- network ------------------------------------------------------------------

    @staticmethod
    def _get(url: str) -> dict:
        req = urllib.request.Request(url, headers={"User-Agent": "netapp-monitor",
                                                   "Accept": "application/rdap+json, application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())

    def _load_servers(self) -> dict[str, str]:
        path = self.bootstrap_path
        fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < BOOTSTRAP_MAX_AGE
        if not fresh:
            try:
                data = self._get(BOOTSTRAP_URL)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    json.dump(data, f)
            except (OSError, ValueError) as e:
                print(f"netapp-monitor: could not update the RDAP server list: {e}", file=sys.stderr)
        try:
            with open(path) as f:
                return servers_from_bootstrap(json.load(f))
        except (OSError, ValueError):
            return {}

    def lookup(self, name: str) -> float | None:
        """Ask the TLD's registry; None when it has no record or no date."""
        if self.servers is None:
            self.servers = self._load_servers()
        base = self.servers.get(name.rsplit(".", 1)[-1])
        if not base:
            return None
        try:
            return registration_date(self._get(f"{base}domain/{name}"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise  # rate limited: try again later
            return None  # 404 and friends: nothing on record

    def _run(self):
        while True:
            name = self.jobs.get()
            try:
                self.record(name, self.lookup(name))
            except (OSError, ValueError) as e:  # offline, rate limited or a bad answer: try later
                with self.lock:
                    self.queued.discard(name)
                    self.failed[name] = time.time()
                if isinstance(e, urllib.error.HTTPError):
                    time.sleep(60)
            if self.jobs.empty():
                try:
                    self.save()
                except OSError:
                    pass
            time.sleep(MIN_GAP)
