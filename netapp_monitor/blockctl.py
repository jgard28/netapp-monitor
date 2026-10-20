#!/usr/bin/python3 -I
"""Privileged helper that cuts processes off from the internet, and gives them back.

Blocked processes are moved into their own cgroup, /sys/fs/cgroup/netapp-blocked, and an
nftables rule rejects every outgoing packet from sockets created in that cgroup, except on
loopback. Children inherit the cgroup, so anything the app spawns is blocked too. Sockets
the app already had open are killed with `ss -K` so it has to reconnect (and fail).

Runs as root through pkexec (see data/*.policy); only processes owned by the calling user
can be blocked. The unprivileged GUI imports this module just to read the current state.

    netapp-blockctl block PID...
    netapp-blockctl unblock PID... | --all
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

CGROUP_ROOT = "/sys/fs/cgroup"
CGROUP_NAME = "netapp-blocked"
CGROUP = f"{CGROUP_ROOT}/{CGROUP_NAME}"
STATE = "/run/netapp-monitor/blocked.json"
TABLE = "netapp_monitor"
INSTALLED_PATH = "/usr/local/libexec/netapp-monitor/netapp-blockctl"

RULESET = f"""\
table inet {TABLE} {{
    chain output {{
        type filter hook output priority filter; policy accept;
        socket cgroupv2 level 1 "{CGROUP_NAME}" oifname != "lo" counter reject
    }}
}}
"""


# --- read-only helpers (safe to call unprivileged) -------------------------------

def blocked_pids() -> set[int]:
    try:
        with open(f"{CGROUP}/cgroup.procs") as f:
            return {int(line) for line in f if line.strip()}
    except OSError:
        return set()


def blocked_since() -> dict[int, float]:
    try:
        with open(STATE) as f:
            return {int(pid): info["since"] for pid, info in json.load(f).items()}
    except (OSError, ValueError, KeyError):
        return {}


def installed() -> bool:
    return os.access(INSTALLED_PATH, os.X_OK)


def cgroup_of(pid: int) -> str:
    with open(f"/proc/{pid}/cgroup") as f:
        for line in f:
            if line.startswith("0::"):
                return line[3:].strip()
    return ""


def children_map() -> dict[int, list[int]]:
    kids: dict[int, list[int]] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as f:
                # The command name can contain spaces and parens; the ppid follows the last ')'.
                ppid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            continue
        kids.setdefault(ppid, []).append(int(entry))
    return kids


def with_descendants(pids, kids) -> list[int]:
    out, stack = [], list(pids)
    while stack:
        pid = stack.pop()
        if pid not in out:
            out.append(pid)
            stack.extend(kids.get(pid, []))
    return out


# --- privileged operations --------------------------------------------------------

def caller_uid() -> int:
    for var in ("PKEXEC_UID", "SUDO_UID"):
        if os.environ.get(var, "").isdigit():
            return int(os.environ[var])
    return os.getuid()


def owner(pid: int) -> int:
    return os.stat(f"/proc/{pid}").st_uid


def load_state() -> dict[str, dict]:
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE), mode=0o755, exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, STATE)


def move(pid: int, cgroup_dir: str) -> bool:
    try:
        with open(f"{cgroup_dir}/cgroup.procs", "w") as f:
            f.write(str(pid))
        return True
    except OSError:
        return False


def kill_sockets(pids):
    """Close the processes' existing non-loopback connections so they can't keep using them."""
    try:
        import psutil
    except ImportError:
        return
    for pid in pids:
        try:
            conns = psutil.Process(pid).net_connections(kind="inet")
        except psutil.Error:
            continue
        for c in conns:
            if not c.raddr or c.raddr.ip.startswith("127.") or c.raddr.ip == "::1":
                continue
            dst = f"[{c.raddr.ip}]" if ":" in c.raddr.ip else c.raddr.ip
            subprocess.run(["ss", "-K", "-n", "-t", "-u", "dst", dst, "dport", "=", f":{c.raddr.port}",
                            "sport", "=", f":{c.laddr.port}"], capture_output=True)


def block(pids: list[int]) -> int:
    uid = caller_uid()
    for pid in pids:
        if pid <= 1 or not os.path.exists(f"/proc/{pid}"):
            sys.exit(f"pid {pid}: no such process")
        if uid != 0 and owner(pid) != uid:
            sys.exit(f"pid {pid}: not your process; refusing to block it")
    targets = [p for p in with_descendants(pids, children_map())
               if os.path.exists(f"/proc/{p}") and (uid == 0 or owner(p) == uid)]

    os.makedirs(CGROUP, exist_ok=True)
    subprocess.run(["nft", "-f", "-"], input=f"add table inet {TABLE}\ndelete table inet {TABLE}\n" + RULESET,
                   text=True, check=True)
    state = load_state()
    moved = []
    for pid in targets:
        origin = cgroup_of(pid)
        if origin == f"/{CGROUP_NAME}":
            continue
        if move(pid, CGROUP):
            state[str(pid)] = {"origin": origin, "since": time.time(), "uid": owner(pid)}
            moved.append(pid)
    save_state(state)
    kill_sockets(moved)
    print(f"blocked {len(moved)} process(es)")
    return 0


def exe_of(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def parent_of(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat") as f:
            return int(f.read().rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return 0


def restore_candidates(pid: int, state: dict, uid: int):
    """Where to put a process back, best first.

    Processes the app started while blocked have no recorded origin, so they follow their
    nearest ancestor. The last resort is a leaf cgroup of our own: slices such as app.slice
    have controllers enabled and refuse to hold processes directly.
    """
    info = state.get(str(pid))
    if info and info.get("origin"):
        yield CGROUP_ROOT + info["origin"]
    parent = parent_of(pid)
    while parent > 1:
        info = state.get(str(parent))
        if info and info.get("origin"):
            yield CGROUP_ROOT + info["origin"]
        try:
            where = cgroup_of(parent)
        except OSError:
            where = ""
        if where and where != f"/{CGROUP_NAME}":
            yield CGROUP_ROOT + where
            break
        parent = parent_of(parent)
    leaf = f"{CGROUP_ROOT}/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/netapp-restored"
    os.makedirs(leaf, exist_ok=True)
    yield leaf


def unblock(pids: list[int] | None) -> int:
    uid = caller_uid()
    current = blocked_pids()
    if pids is None:
        targets = current
    else:
        # Unblocking an app covers every blocked process of it, including ones it started
        # after the GUI last looked, and their children.
        exes = {exe_of(p) for p in pids} - {""}
        chosen = {p for p in current if p in pids or exe_of(p) in exes}
        targets = set(with_descendants(chosen, children_map())) & current
    state = load_state()
    # Recorded processes first, so their children can follow them back.
    ordered = sorted(targets, key=lambda p: (str(p) not in state, p))
    restored, failed = 0, []
    for pid in ordered:
        try:
            pid_uid = state.get(str(pid), {}).get("uid", owner(pid))
        except OSError:
            continue  # exited
        if uid != 0 and pid_uid != uid:
            continue
        if any(move(pid, cg) for cg in restore_candidates(pid, state, pid_uid)):
            restored += 1
        elif os.path.exists(f"/proc/{pid}"):
            failed.append(pid)
    remaining = blocked_pids()
    save_state({p: i for p, i in state.items() if int(p) in remaining})
    if not remaining:
        subprocess.run(["nft", "delete", "table", "inet", TABLE], capture_output=True)
        try:
            os.rmdir(CGROUP)
        except OSError:
            pass
    print(f"unblocked {restored} process(es)")
    if failed:
        print(f"could not unblock pid(s) {', '.join(map(str, failed))}; they are still blocked",
              file=sys.stderr)
        return 1
    return 0


def main(argv) -> int:
    if os.geteuid() != 0:
        sys.exit("netapp-blockctl must run as root (via pkexec)")
    if len(argv) >= 2 and argv[0] == "block":
        return block([int(a) for a in argv[1:]])
    if argv == ["unblock", "--all"]:
        return unblock(None)
    if len(argv) >= 2 and argv[0] == "unblock":
        return unblock([int(a) for a in argv[1:]])
    sys.exit(__doc__.split("\n\n")[-1])


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ValueError:
        sys.exit("PIDs must be numbers")
    except subprocess.CalledProcessError as e:
        sys.exit(f"nft failed: {e}")
