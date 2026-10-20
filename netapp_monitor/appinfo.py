"""Facts about a running app: which package installed it, whether it's still the file the
package shipped, its hash, and how it was launched."""
from __future__ import annotations

import gzip
import hashlib
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

import psutil
from PySide6.QtCore import QObject, Signal

from .collector import HIGH, Alert

PACMAN_DB = "/var/lib/pacman/local"
DPKG_INFO = "/var/lib/dpkg/info"
ENV_C = dict(os.environ, LC_ALL="C")


def _run(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, env=ENV_C, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def owning_package(path: str) -> str | None:
    """'firefox 158.0-1' if a package manager installed this file, else None."""
    if shutil.which("pacman"):
        out = _run(["pacman", "-Qo", path], 10)
        if out and out.returncode == 0 and " is owned by " in out.stdout:
            return out.stdout.strip().rsplit(" is owned by ", 1)[1]
    elif shutil.which("dpkg"):
        out = _run(["dpkg", "-S", path], 10)
        if out and out.returncode == 0:
            return out.stdout.split(": ", 1)[0]
    elif shutil.which("rpm"):
        out = _run(["rpm", "-qf", path], 10)
        if out and out.returncode == 0:
            return out.stdout.strip()
    return None


def file_hash(path: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256(path: str) -> str:
    return file_hash(path, "sha256")


def _mtree_unescape(path: str) -> str:
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), path)


def packaged_hash(path: str, package: str) -> tuple[str, str] | None:
    """(algorithm, digest) the package database recorded for this file, if any."""
    if os.path.isdir(PACMAN_DB):
        name, _, version = package.partition(" ")
        mtree = f"{PACMAN_DB}/{name}-{version}/mtree"
        try:
            with gzip.open(mtree, "rt", errors="replace") as f:
                for line in f:
                    entry, *attrs = line.split()
                    if _mtree_unescape(entry) == "." + path:
                        for attr in attrs:
                            if attr.startswith("sha256digest="):
                                return "sha256", attr.split("=", 1)[1]
        except OSError:
            return None
    elif os.path.isdir(DPKG_INFO):
        for md5sums in (f"{DPKG_INFO}/{package}.md5sums", f"{DPKG_INFO}/{package.split(':')[0]}.md5sums"):
            try:
                with open(md5sums) as f:
                    for line in f:
                        digest, _, rel = line.strip().partition("  ")
                        if "/" + rel == path:
                            return "md5", digest
            except OSError:
                continue
    return None


MISMATCH = re.compile(r"^(?:warning: )?[^:]+: (/.*) \((.+)\)$")
CONTENT_CHANGES = ("Size mismatch", "SHA256 checksum mismatch", "MD5 checksum mismatch",
                   "File type mismatch", "Symlink path mismatch")


def verify_package(package: str) -> dict | None:
    """Check every file of the package against the package database.

    {"files": total or None, "changed": [(path, reason)], "unreadable": n}. Only content
    changes count as changed; files you can't read without root are just counted.
    """
    name = package.partition(" ")[0]
    if shutil.which("pacman"):
        out = _run(["pacman", "-Qkk", name], 300)
        if out is None:
            return None
        changed, unreadable, total = [], 0, None
        for line in (out.stdout + out.stderr).splitlines():
            if " total files, " in line:
                total = int(re.search(r"(\d+) total files", line).group(1))
            elif m := MISMATCH.match(line):
                path, reason = m.groups()
                if "Permission denied" in reason:
                    unreadable += 1
                elif reason in CONTENT_CHANGES or reason.startswith("No such file"):
                    changed.append((path, reason))
        return {"files": total, "changed": changed, "unreadable": unreadable}
    if shutil.which("dpkg"):
        out = _run(["dpkg", "--verify", name.split(":")[0]], 300)
        if out is None:
            return None
        # dpkg prints only problems, e.g. "??5??????   /usr/bin/foo" (5 = checksum differs).
        changed = [(l.split()[-1], "checksum mismatch") for l in out.stdout.splitlines()
                   if len(l) > 2 and l[2] == "5"]
        return {"files": None, "changed": changed, "unreadable": 0}
    return None


def parent_chain(pid: int, limit: int = 8) -> list[tuple[str, int]]:
    """[(name, pid), ...] from the process's parent up towards init."""
    try:
        parents = psutil.Process(pid).parents()
    except psutil.Error:
        return []
    chain = []
    for p in parents[:limit]:
        try:
            chain.append((p.name(), p.pid))
        except psutil.Error:
            chain.append(("?", p.pid))
    return chain


def started(pid: int) -> float | None:
    try:
        return psutil.Process(pid).create_time()
    except psutil.Error:
        return None


class AppInfoLoader(QObject):
    """Looks up package, hash and integrity off the UI thread, cached per file version.

    `loaded` fires once with package/hash/exe_matches, and again when the slower full
    package verification (requested by the detail panel) finishes.
    """

    loaded = Signal(str, dict)

    def __init__(self):
        super().__init__()
        self.cache: dict[tuple, dict] = {}
        self.pending: set[tuple] = set()
        self.want_verify: set[tuple] = set()  # verification asked for while the lookup was still running
        self.pool = ThreadPoolExecutor(2)

    @staticmethod
    def _key(exe):
        try:
            st = os.stat(exe)
            return (exe, st.st_mtime, st.st_size)
        except OSError:
            return (exe, None, None)

    def cached(self, exe: str) -> dict | None:
        return self.cache.get(self._key(exe))

    def request(self, exe: str, verify: bool = False):
        key = self._key(exe)
        info = self.cache.get(key)
        if info is not None:
            self.loaded.emit(exe, info)
            if verify and "verify" not in info and info["package"] and (key, "verify") not in self.pending:
                self.pending.add((key, "verify"))
                self.pool.submit(self._verify, exe, key)
            return
        if verify:
            self.want_verify.add(key)
        if key not in self.pending:
            self.pending.add(key)
            self.pool.submit(self._work, exe, key)

    def _work(self, exe, key):
        info = {"package": owning_package(exe), "sha256": None, "exe_matches": None, "error": None}
        try:
            info["sha256"] = sha256(exe)
            recorded = packaged_hash(exe, info["package"]) if info["package"] else None
            if recorded:
                algo, digest = recorded
                actual = info["sha256"] if algo == "sha256" else file_hash(exe, algo)
                info["exe_matches"] = actual == digest
        except OSError as e:
            info["error"] = e.strerror or str(e)
        self.cache[key] = info
        self.pending.discard(key)
        self.loaded.emit(exe, info)
        if key in self.want_verify and info["package"]:
            self.want_verify.discard(key)
            self.pending.add((key, "verify"))
            self._verify(exe, key)

    def _verify(self, exe, key):
        info = self.cache[key]
        info["verify"] = verify_package(info["package"])
        self.pending.discard((key, "verify"))
        self.loaded.emit(exe, info)

    def alert_for(self, proc) -> Alert | None:
        """High alert if the program differs from what its package installed (looked up lazily)."""
        if not proc.exe:
            return None
        info = self.cached(proc.exe)
        if info is None:
            self.request(proc.exe)
            return None
        if info["exe_matches"] is False:
            return Alert(HIGH, f"Program file differs from the copy {info['package']} installed "
                               "(possibly tampered with or trojanized)", kind="never-mute")
        return None
