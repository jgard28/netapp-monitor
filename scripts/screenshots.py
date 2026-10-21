#!/usr/bin/env python3
"""Render the README screenshots and demo GIF from made-up data.

Nothing here looks at your machine: the dashboard is fed a fixed set of fictional apps and
connections (documentation IP ranges, invented paths), runs offscreen with a throwaway home
directory, sends no notifications and downloads nothing. Re-run it after UI changes:

    python3 scripts/screenshots.py          # writes docs/screenshots/*.png and docs/demo.gif

Needs Pillow (python-pillow) besides the app's own dependencies.
"""
from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
import time
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs"
THEME = Path("/usr/share/omarchy/themes/tokyo-night/colors.toml")
TOKYO_NIGHT = """\
accent = "#7aa2f7"
cursor = "#c0caf5"
foreground = "#a9b1d6"
background = "#1a1b26"
selection_foreground = "#c0caf5"
selection_background = "#7aa2f7"
color0 = "#32344a"
color4 = "#7aa2f7"
color8 = "#444b6a"
"""

# Isolate everything the app reads or writes before it's imported (paths are fixed at import).
HOME = tempfile.mkdtemp(prefix="netapp-demo-")
atexit.register(shutil.rmtree, HOME, ignore_errors=True)
for var, sub in (("HOME", ""), ("XDG_CONFIG_HOME", ".config"), ("XDG_CACHE_HOME", ".cache"),
                 ("XDG_STATE_HOME", ".local/state"), ("XDG_DATA_HOME", ".local/share")):
    os.environ[var] = os.path.join(HOME, sub)
os.environ["QT_QPA_PLATFORM"] = "offscreen"
theme = Path(HOME, ".local/state/omarchy/current/theme/colors.toml")
theme.parent.mkdir(parents=True)
theme.write_text(THEME.read_text() if THEME.exists() else TOKYO_NIGHT)
sys.path.insert(0, str(ROOT))

from PIL import Image  # noqa: E402
from PySide6.QtCore import QBuffer, QObject, QPoint, QPointF, Qt, Signal  # noqa: E402
from PySide6.QtGui import QColor, QPainter, QPen, QPolygonF  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication, QScrollArea  # noqa: E402

from netapp_monitor import gui, panel  # noqa: E402
from netapp_monitor.collector import HIGH, LOW, MEDIUM, Alert, Connection, Process  # noqa: E402
from netapp_monitor.geo import Owner  # noqa: E402

NOW = time.time()
ME = "alex"
LAN = "192.168.1."
CF = Owner(13335, "US", "Cloudflare, Inc.", False)
GOOGLE = Owner(15169, "US", "Google LLC", False)
FASTLY = Owner(54113, "US", "Fastly, Inc.", False)
AKAMAI = Owner(20940, "NL", "Akamai International B.V.", False)
VALVE = Owner(32590, "US", "Valve Corporation", False)
HETZNER = Owner(24940, "DE", "Hetzner Online GmbH", True)
OVH = Owner(16276, "FR", "OVH SAS", True)
SHADY = Owner(209588, "NL", "Flyservers S.A.", True)
GH = Owner(36459, "US", "GitHub, Inc.", False)

PROCS = {  # pid -> (start offset in seconds, parent chain, package or None)
    48211: (240, [("python3", 48190), ("bash", 47702), ("kitty", 2210)], None),
    48190: (260, [("bash", 47702), ("kitty", 2210)], "python"),
    51007: (95, [("cron", 911), ("systemd", 1)], None),
    3120: (7200, [("Hyprland", 1980), ("systemd", 1)], "firefox"),
    3388: (6900, [("Hyprland", 1980), ("systemd", 1)], None),
    2875: (7300, [("systemd", 1)], "syncthing"),
    4410: (5400, [("steam", 4402), ("Hyprland", 1980)], None),
    1204: (9000, [("systemd", 1)], "nextcloud-client"),
    6630: (1800, [("code", 6601), ("Hyprland", 1980)], "code"),
}


def conn(pid, raddr, rport, owner=None, domain="", alerts=(), new=False, proto="tcp", status="ESTABLISHED",
         scope="internet", up=0.0, down=0.0, lport=None, device=""):
    return Connection(pid, proto, "192.168.1.42" if scope != "loopback" else "127.0.0.1",
                      lport or 40000 + (hash((pid, raddr, rport)) % 20000), raddr, rport, status, scope,
                      list(alerts), new, domain, owner, device, [], int(down * 41), int(down * 97), up, down)


def demo_procs() -> list[Process]:
    """A desktop on a bad day: a dropped binary, a reverse shell, a beacon, and the usual apps."""
    c2 = "Botnet C2 (AsyncRAT)"
    return [
        Process(48211, "system-updater", "/dev/shm/system-updater", cmdline="/dev/shm/system-updater --silent",
                user=ME, new=True, alerts=[Alert(HIGH, "Runs from a temp directory: /dev/shm/system-updater",
                                                 topic="temp")],
                connections=[
                    conn(48211, "198.51.100.23", 4444, SHADY, alerts=[
                        Alert(HIGH, f"ThreatFox: {c2} (port 4444 matches, first seen 2026-10-19, confidence 100%)",
                              kind="intel", topic="intel"),
                        Alert(MEDIUM, "Remote port 4444: Metasploit default handler", topic="port")], new=True,
                         up=310, down=95),
                    conn(48211, "198.51.100.24", 443, SHADY, domain="cdn-update-sync.top", new=True, alerts=[
                        Alert(MEDIUM, "cdn-update-sync.top was registered 3 days ago", topic="domain-age")])]),
        Process(48190, "bash", "/usr/bin/bash", cmdline="bash -i", user=ME,
                alerts=[Alert(HIGH, "bash has an internet connection (possible reverse shell)", topic="shell")],
                connections=[conn(48190, "203.0.113.77", 443, HETZNER, new=True, up=120, down=88)]),
        Process(None, "DNS lookup (app unknown)", connections=[], alerts=[
            Alert(HIGH, "Something looked up qx7v2kpl9d.duckdns.org: URLhaus: malware download "
                        "(first seen 2026-10-20)", kind="intel", topic="intel-dns")]),
        Process(51007, "curl", "/usr/bin/curl", cmdline="curl -s https://203.0.113.140/api/checkin", user=ME,
                alerts=[Alert(LOW, "Uploaded 18.4 MB in the last 10 min", topic="upload")],
                connections=[conn(51007, "203.0.113.140", 443, OVH, new=True, alerts=[
                    Alert(MEDIUM, "Beaconing: reconnects every ~30s", topic="beacon")], up=31000, down=600)]),
        Process(3120, "firefox", "/usr/lib/firefox/firefox", cmdline="/usr/lib/firefox/firefox", user=ME,
                connections=[
                    conn(3120, "104.16.132.229", 443, CF, domain="www.wikipedia.org", down=48200, up=1900),
                    conn(3120, "142.250.180.14", 443, GOOGLE, domain="www.youtube.com", down=812000, up=9100),
                    conn(3120, "151.101.1.140", 443, FASTLY, domain="www.reddit.com", down=3100, up=400),
                    conn(3120, "140.82.112.4", 443, GH, domain="github.com", down=650, up=120),
                    conn(3120, "23.62.199.8", 443, AKAMAI, domain="assets.example-shop.com", new=True, down=210)]),
        Process(3388, "Discord", "/opt/discord/Discord", cmdline="/opt/discord/Discord", user=ME,
                connections=[conn(3388, "162.159.135.234", 443, CF, domain="gateway.discord.gg", down=900, up=300),
                             conn(3388, "162.159.128.233", 443, CF, domain="cdn.discordapp.com", down=4300)]),
        Process(4410, "steamwebhelper", "/home/alex/.local/share/Steam/ubuntu12_64/steamwebhelper",
                cmdline="steamwebhelper", user=ME, alerts=[], connections=[
                    conn(4410, "23.32.10.110", 443, VALVE, domain="store.steampowered.com", down=12000, up=700)]),
        Process(1204, "nextcloud", "/usr/bin/nextcloud", cmdline="/usr/bin/nextcloud --background", user=ME,
                connections=[conn(1204, "203.0.113.200", 443, HETZNER, domain="cloud.example.net", alerts=[
                    Alert(MEDIUM, "Beaconing: reconnects every ~60s", topic="beacon", muted=True)], down=50)]),
        Process(6630, "code", "/opt/visual-studio-code/code", cmdline="code", user=ME,
                connections=[conn(6630, "140.82.113.21", 443, GH, domain="api.github.com", down=1300, up=200)]),
        Process(2875, "syncthing", "/usr/bin/syncthing", cmdline="syncthing serve --no-browser", user=ME,
                connections=[
                    conn(2875, LAN + "20", 22000, scope="lan", device="nas", down=96000, up=410000),
                    conn(2875, LAN + "31", 22000, scope="lan", device="pixel-phone", down=1200, up=800),
                    conn(2875, "198.51.100.180", 443, OVH, domain="relays.syncthing.net", down=90)]),
        Process(2210, "kitty", "/usr/bin/kitty", cmdline="kitty", user=ME, connections=[
            conn(2210, LAN + "10", 22, scope="lan", device="proxmox-node1", down=300, up=150),
            conn(2210, LAN + "11", 8006, scope="lan", device="proxmox-node2", down=2000, up=200)]),
    ]


INFO = {  # exe -> what the package check would find
    "/dev/shm/system-updater": dict(package=None, error="", exe_matches=None, verify=None,
                                    sha256="9f2c4e1b7a33d0c58e6f1a2b4c7d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f801"),
}


def fake_info(exe):
    if exe in INFO:
        return INFO[exe]
    pkg = next((p for pid, (_, _, p) in PROCS.items() if p and exe.endswith(p.split("-")[0])), None)
    pkg = pkg or {"/usr/bin/bash": "bash", "/usr/bin/curl": "curl", "/usr/bin/kitty": "kitty"}.get(exe)
    return dict(package=pkg, error="", exe_matches=True if pkg else None, sha256="3b7e" + "a5c1d2" * 10,
                verify={"changed": [], "files": 214, "unreadable": 0} if pkg else None)


class NoDns:
    status = "watching"
    watching_since = NOW - 3 * 3600


class NoNotify(QObject):
    show_requested = Signal(object)
    available = False

    def send(self, *a, **k):
        pass


def patch():
    gui.Dashboard.load_intel = lambda self: None
    gui.analyze = lambda *a, **k: demo_procs()
    gui.snapshot = lambda: []
    gui.arp_table = lambda: {}
    gui.merge_shared = lambda procs, parents=None: [setattr(p, "pids", [p.pid] if p.pid else []) or p for p in procs]
    gui.DnsWatcher = NoDns
    gui.GeoDB = lambda *a, **k: None
    gui.Notifier = NoNotify
    gui.Resolver.get = lambda self, ip: ""
    names = {LAN + "20": "nas", LAN + "31": "pixel-phone", LAN + "10": "proxmox-node1", LAN + "11": "proxmox-node2"}
    gui.DeviceNames.name_for = lambda self, ip, arp=None: names.get(ip, "")
    panel.started = lambda pid: NOW - PROCS[pid][0] if pid in PROCS else NOW - 4000
    panel.parent_chain = lambda pid, limit=8: PROCS.get(pid, (0, [("systemd", 1)]))[1]
    gui.AppInfoLoader.request = lambda self, exe, verify=False: self.loaded.emit(exe, fake_info(exe))


def cursor(pix, at: QPoint):
    """Draw a mouse pointer so the GIF shows what was clicked."""
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)
    x, y = at.x(), at.y()
    pts = [(0, 0), (0, 21), (5, 16), (9, 25), (12, 24), (8, 15), (15, 15)]
    poly = QPolygonF([QPointF(x + a, y + b) for a, b in pts])
    p.setPen(QPen(QColor("black"), 1.5))
    p.setBrush(QColor("white"))
    p.drawPolygon(poly)
    p.end()
    return pix


def to_image(pix) -> Image.Image:
    buf = QBuffer()
    buf.open(QBuffer.ReadWrite)
    pix.save(buf, "PNG")
    return Image.open(BytesIO(bytes(buf.data()))).convert("RGB")


def main():
    patch()
    app = QApplication(sys.argv)
    app.setApplicationName("NetApp Monitor")
    d = gui.Dashboard(has_tray=False)
    d.baseline.created = NOW - 86400  # past the learning period
    for p in demo_procs():  # every app but the new ones has been seen before
        if not p.new and p.exe:
            d.baseline.apps[p.exe] = {"first": NOW - 12 * 86400, "dests": {f"n{i}": 0 for i in range(9)}}
    d.trust.apps["/usr/bin/nextcloud"] = NOW - 5 * 86400
    d.blocklist.counts = {"ThreatFox": 4812, "Feodo Tracker": 391, "URLhaus": 18733, "Spamhaus DROP": 1402}
    d.expanded.add((3120, "/usr/lib/firefox/firefox"))
    d.resize(1440, 820)
    d.show()
    d.tick()
    d.tree.setFocus()
    app.processEvents()

    shots = OUT / "screenshots"
    shots.mkdir(parents=True, exist_ok=True)
    frames = []  # (image, milliseconds)

    def settle():
        for _ in range(5):
            app.processEvents()

    def grab(click: QPoint | None = None):
        settle()
        pix = d.grab()
        return cursor(pix, click) if click else pix

    def row(name):
        for i in range(d.tree.topLevelItemCount()):
            item = d.tree.topLevelItem(i)
            if item.text(0).startswith(name):
                return item
        raise LookupError(name)

    def click_row(name, show=0):
        """Click an app's row; with `show`, first add a GIF frame of the pointer over it."""
        rect = d.tree.visualItemRect(row(name))
        pos = rect.topLeft() + QPoint(60, rect.height() // 2)
        if show:
            frames.append((to_image(grab(d.tree.viewport().mapTo(d, pos))), show))
        QTest.mouseClick(d.tree.viewport(), Qt.LeftButton, pos=pos)

    # 1. Overview: flagged apps first and expanded, the detail panel closed.
    overview = grab()
    overview.save(str(shots / "overview.png"))
    frames.append((to_image(overview), 3000))

    # 2. Click the dropped binary: the detail panel explains what it is.
    click_row("system-updater", show=1200)
    details = grab()
    details.save(str(shots / "details.png"))
    frames.append((to_image(details), 3500))

    # 3. "What does this mean?" on the first alert.
    d.details._toggle_explanation(0)
    settle()
    scroll = d.details.findChild(QScrollArea).verticalScrollBar()
    scroll.setValue(scroll.maximum())
    explained = grab()
    explained.save(str(shots / "explanation.png"))
    frames.append((to_image(explained), 5000))

    # 4. Another app: the reverse shell.
    click_row("bash", show=1200)
    frames.append((to_image(grab()), 3500))

    # 5. Local network view.
    d.close_details()
    d.expanded.update({(2875, "/usr/bin/syncthing"), (2210, "/usr/bin/kitty")})
    d.set_view("local")
    local = grab()
    local.save(str(shots / "local-network.png"))
    frames.append((to_image(local), 3000))

    # 6. Tiled half-screen: the panel moves under the list.
    d.set_view("internet")
    d.resize(900, 1000)
    settle()
    click_row("system-updater")
    grab().save(str(shots / "tiled.png"))

    w = 1080
    images = [im.resize((w, im.height * w // im.width), Image.Resampling.LANCZOS) for im, _ in frames]
    palette = images[1].quantize(colors=255, method=Image.Quantize.MEDIANCUT)  # one with the panel's colors too
    gif = [im.quantize(palette=palette, dither=Image.Dither.NONE) for im in images]
    gif[0].save(OUT / "demo.gif", save_all=True, append_images=gif[1:], duration=[ms for _, ms in frames],
                loop=0, optimize=True)
    for f in sorted(shots.iterdir()) + [OUT / "demo.gif"]:
        print(f"{f.relative_to(ROOT)}  {f.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
