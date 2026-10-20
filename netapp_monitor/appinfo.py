"""Facts about a running app: which package installed it, its hash, and how it was launched."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import threading

import psutil
from PySide6.QtCore import QObject, Signal


def owning_package(path: str) -> str | None:
    """'firefox 158.0-1' if a package manager installed this file, else None."""
    env = dict(os.environ, LC_ALL="C")
    try:
        if shutil.which("pacman"):
            out = subprocess.run(["pacman", "-Qo", path], capture_output=True, text=True, env=env, timeout=10)
            if out.returncode == 0 and " is owned by " in out.stdout:
                return out.stdout.strip().rsplit(" is owned by ", 1)[1]
        elif shutil.which("dpkg"):
            out = subprocess.run(["dpkg", "-S", path], capture_output=True, text=True, env=env, timeout=10)
            if out.returncode == 0:
                return out.stdout.split(":", 1)[0]
        elif shutil.which("rpm"):
            out = subprocess.run(["rpm", "-qf", path], capture_output=True, text=True, env=env, timeout=10)
            if out.returncode == 0:
                return out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


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
    """Looks up package ownership and hash off the UI thread, cached per file version."""

    loaded = Signal(str, dict)  # exe, {"package": str|None, "sha256": str|None, "error": str|None}

    def __init__(self):
        super().__init__()
        self.cache: dict[tuple, dict] = {}
        self.pending: set[tuple] = set()

    def _key(self, exe):
        try:
            st = os.stat(exe)
            return (exe, st.st_mtime, st.st_size)
        except OSError:
            return (exe, None, None)

    def request(self, exe: str):
        key = self._key(exe)
        if key in self.cache:
            self.loaded.emit(exe, self.cache[key])
        elif key not in self.pending:
            self.pending.add(key)
            threading.Thread(target=self._work, args=(exe, key), daemon=True).start()

    def _work(self, exe, key):
        info = {"package": owning_package(exe), "sha256": None, "error": None}
        try:
            info["sha256"] = sha256(exe)
        except OSError as e:
            info["error"] = e.strerror or str(e)
        self.cache[key] = info
        self.pending.discard(key)
        self.loaded.emit(exe, info)
