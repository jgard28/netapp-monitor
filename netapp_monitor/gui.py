"""Tray icon plus a dashboard window listing every app's network connections."""
from __future__ import annotations

import hashlib
import os
import re
import signal
import sys
import threading
import time
from pathlib import Path

import psutil
from PySide6.QtCore import QProcess, Qt, QTimer, QUrl
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QGuiApplication, QIcon, QPainter, QPen, QPixmap
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QCheckBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMenu, QMessageBox, QPushButton, QStackedWidget, QSystemTrayIcon, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from . import blockctl, intel
from .collector import HIGH, MEDIUM, SEVERITY_NAMES, Resolver, snapshot, visible_connections
from .detect import BeaconTracker, analyze
from .notifier import Notifier

APP_ID = "netapp-monitor"
REFRESH_MS = 3000
INTEL_REFRESH_MS = 30 * 60 * 1000  # each feed only re-downloads once its cache is stale
POPUP_TIMEOUT_MS = {HIGH: 20000, MEDIUM: 12000}  # pop-ups close themselves after this
POPUP_BATCH = 3  # more new alerts than this in one refresh become a single summary pop-up
SEVERITY_COLORS = {0: "#3fb950", 1: "#d29922", 2: "#f0883e", 3: "#f85149"}
BLOCKED_COLOR = "#8b949e"
COLUMNS = ["Application / connection", "PID", "User", "Proto", "Local", "Remote", "Host", "State", "Scope", "Alerts"]
ROLE = Qt.UserRole
SETUP_SCRIPT = Path(__file__).resolve().parent.parent / "install-blocking.sh"


def tray_icon(severity: int) -> QIcon:
    """A radar-style dot whose color is the worst alert currently seen."""
    pix = QPixmap(64, 64)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)
    color = QColor(SEVERITY_COLORS[severity])
    p.setPen(QPen(color, 5))
    p.setBrush(Qt.NoBrush)
    p.drawEllipse(6, 6, 52, 52)
    p.drawEllipse(18, 18, 28, 28)
    p.setPen(Qt.NoPen)
    p.setBrush(color)
    p.drawEllipse(26, 26, 12, 12)
    p.end()
    return QIcon(pix)


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ago(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"


def same_app_pids(proc) -> list[int]:
    """Every process of yours running the same executable, so the whole app gets blocked."""
    if not proc.exe:
        return [proc.pid]
    uid = os.getuid()
    pids = []
    for p in psutil.process_iter(["exe", "uids"]):
        if p.info["exe"] == proc.exe and p.info["uids"] and p.info["uids"].real == uid:
            pids.append(p.pid)
    return pids or [proc.pid]


class Dashboard(QMainWindow):
    def __init__(self, has_tray: bool):
        super().__init__()
        self.has_tray = has_tray
        self.setWindowTitle("NetApp Monitor")
        self.resize(1200, 700)
        self.procs = []
        self.blocklist = intel.Intel()
        self.blocked_pids: set[int] = set()
        self.blocked_apps: list[dict] = []
        self.tracker = BeaconTracker()
        self.resolver = Resolver()
        self.expanded: set = set()
        self.auto_expanded: set = set()
        self.notified: set = set()
        self.helper: QProcess | None = None

        # View switcher: Connections | Blocked
        self.conn_tab = QPushButton("Connections", checkable=True, checked=True)
        self.block_tab = QPushButton("Blocked", checkable=True)
        tabs = QButtonGroup(self)
        tabs.setExclusive(True)
        for i, b in enumerate((self.conn_tab, self.block_tab)):
            b.setFlat(True)
            tabs.addButton(b, i)
        tabs.idClicked.connect(self.switch_page)
        switcher = QHBoxLayout()
        switcher.addWidget(self.conn_tab)
        switcher.addWidget(self.block_tab)
        switcher.addStretch(1)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._connections_page())
        self.pages.addWidget(self._blocked_page())

        self.status = QLabel()
        layout = QVBoxLayout()
        layout.addLayout(switcher)
        layout.addWidget(self.pages, 1)
        layout.addWidget(self.status)
        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)
        self.setStyleSheet("QPushButton:flat { padding: 4px 12px; border: none; border-bottom: 2px solid transparent; }"
                           "QPushButton:flat:checked { border-bottom: 2px solid palette(highlight); font-weight: bold; }")

        self.tray = QSystemTrayIcon(tray_icon(0), self) if has_tray else None
        if self.tray:
            menu = QMenu(self)
            menu.addAction("Show dashboard", self.show_window)
            self.popups = menu.addAction("Pop-up alerts")
            self.popups.setCheckable(True)
            self.popups.setChecked(True)
            menu.addAction("Refresh threat intel", self.load_intel)
            menu.addSeparator()
            menu.addAction("Quit", QApplication.quit)
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self.tray_clicked)
            self.tray.show()

        self.notifier = Notifier()
        self.notifier.show_requested.connect(self.reveal)

        self.timer = QTimer(self, interval=REFRESH_MS, timeout=self.tick)
        self.timer.start()
        self.intel_timer = QTimer(self, interval=INTEL_REFRESH_MS, timeout=self.load_intel)
        self.intel_timer.start()
        self.user_list_mtime = intel.user_list_mtime()
        self.load_intel()
        self.tick()

    def _connections_page(self):
        self.search = QLineEdit(placeholderText="Filter by app, path, PID, IP or host…")
        self.show_all = QCheckBox("Include LAN / loopback / listening")
        self.alerts_only = QCheckBox("Flagged only")
        self.live = QCheckBox("Live", checked=True)
        refresh = QPushButton("Refresh")
        for w in (self.search, self.show_all, self.alerts_only):
            (w.textChanged if w is self.search else w.toggled).connect(self.populate)
        refresh.clicked.connect(self.tick)

        bar = QHBoxLayout()
        bar.addWidget(self.search, 1)
        for w in (self.show_all, self.alerts_only, self.live, refresh):
            bar.addWidget(w)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.setUniformRowHeights(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.context_menu)
        self.tree.itemExpanded.connect(lambda i: self.expanded.add(i.data(0, ROLE)))
        self.tree.itemCollapsed.connect(lambda i: self.expanded.discard(i.data(0, ROLE)))
        header = self.tree.header()
        header.setSectionResizeMode(QHeaderView.Interactive)
        for col, width in enumerate((260, 70, 80, 50, 190, 210, 230, 100, 80)):
            self.tree.setColumnWidth(col, width)
        header.setStretchLastSection(True)

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(bar)
        layout.addWidget(self.tree, 1)
        return page

    def _blocked_page(self):
        intro = QLabel("These apps can't reach the internet or your LAN (loopback still works). "
                       "A block lasts until you unblock the app or it exits.")
        intro.setWordWrap(True)
        self.unblock_all = QPushButton("Unblock all")
        self.unblock_all.clicked.connect(lambda: self.run_helper(["unblock", "--all"]))
        top = QHBoxLayout()
        top.addWidget(intro, 1)
        top.addWidget(self.unblock_all)

        self.blocked_tree = QTreeWidget()
        self.blocked_tree.setHeaderLabels(["Application", "Processes", "Blocked for", "Path", ""])
        self.blocked_tree.setRootIsDecorated(False)
        for col, width in enumerate((220, 90, 110, 520, 110)):
            self.blocked_tree.setColumnWidth(col, width)
        self.blocked_tree.header().setStretchLastSection(False)
        self.blocked_tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self.blocked_empty = QLabel("Nothing is blocked.\n\nTo block an app, right-click it on the "
                                    "Connections page and choose “Block internet access”.")
        self.blocked_empty.setAlignment(Qt.AlignCenter)

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(top)
        layout.addWidget(self.blocked_tree, 1)
        layout.addWidget(self.blocked_empty, 1)
        return page

    # --- data -----------------------------------------------------------------

    def load_intel(self):
        def work():
            self.blocklist = intel.load(update=True)
        threading.Thread(target=work, daemon=True).start()

    def tick(self):
        if intel.user_list_mtime() != self.user_list_mtime:
            self.user_list_mtime = intel.user_list_mtime()
            self.load_intel()
        self.procs = analyze(snapshot(), self.blocklist, self.tracker)
        self.refresh_blocked()
        worst = max((p.severity for p in self.procs), default=0)
        flagged = sum(1 for p in self.procs if p.severity)
        internet = sum(len(p.internet) for p in self.procs)
        summary = (f"{len(self.procs)} apps · {internet} internet connections · {flagged} flagged · "
                   f"{len(self.blocked_apps)} blocked · intel: {self.blocklist.summary() or 'loading…'}")
        self.status.setText(summary)
        if self.tray:
            self.tray.setIcon(tray_icon(worst))
            self.tray.setToolTip(f"NetApp Monitor\n{summary}")
            self.notify()
        if self.isVisible() and self.live.isChecked():
            self.populate()

    def refresh_blocked(self):
        self.blocked_pids = blockctl.blocked_pids()
        since = blockctl.blocked_since()
        apps: dict[str, dict] = {}
        for pid in sorted(self.blocked_pids):
            try:
                p = psutil.Process(pid)
                name, exe = p.name(), p.exe()
            except psutil.Error:
                continue
            app = apps.setdefault(exe or name, {"name": name, "exe": exe, "pids": [], "since": time.time()})
            app["pids"].append(pid)
            app["since"] = min(app["since"], since.get(pid, app["since"]))
        self.blocked_apps = sorted(apps.values(), key=lambda a: a["name"].lower())
        self.block_tab.setText(f"Blocked ({len(self.blocked_apps)})" if self.blocked_apps else "Blocked")

    def notify(self):
        """Pop up each high/medium alert once per session, batching bursts into one summary."""
        fresh = []
        for p in self.procs:
            for a in p.all_alerts():
                # Ignore numbers like the beacon interval so a drifting value doesn't re-alert.
                key = (p.exe or p.name, re.sub(r"~\d+s", "", a.message))
                if a.severity >= MEDIUM and key not in self.notified:
                    self.notified.add(key)
                    fresh.append((p, a))
        if not fresh or not self.popups.isChecked():
            return
        worst = max(a.severity for _, a in fresh)
        if len(fresh) > POPUP_BATCH:
            lines = [f"• {p.name}: {a.message}" for p, a in fresh[:5]]
            if len(fresh) > 5:
                lines.append(f"…and {len(fresh) - 5} more")
            self.popup(f"{len(fresh)} new alerts", "\n".join(lines), worst, None)
            return
        for p, a in fresh:
            label = "Suspicious" if a.severity >= HIGH else "Worth a look"
            self.popup(f"{label}: {p.name} (pid {p.pid})", a.message, a.severity, p.pid)

    def popup(self, title, body, severity, pid):
        timeout = POPUP_TIMEOUT_MS[severity]
        if self.notifier.available:
            self.notifier.send(title, body, timeout, pid)
        else:
            icon = QSystemTrayIcon.Critical if severity >= HIGH else QSystemTrayIcon.Warning
            self.tray.showMessage(title, body, icon, timeout)

    def reveal(self, pid):
        """Open the dashboard on the Connections page with the alerted app selected."""
        self.switch_page(0)
        if pid:
            self.alerts_only.setChecked(False)
            self.search.clear()
        self.show_window()
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            if pid and item.data(1, ROLE).pid == pid:
                item.setExpanded(True)
                self.tree.setCurrentItem(item)
                self.tree.scrollToItem(item, QTreeWidget.PositionAtTop)
                break

    # --- view -----------------------------------------------------------------

    def switch_page(self, index):
        (self.conn_tab, self.block_tab)[index].setChecked(True)
        self.pages.setCurrentIndex(index)
        self.populate()

    def populate(self):
        if self.pages.currentIndex() == 1:
            self.populate_blocked()
            return
        needle = self.search.text().strip().lower()
        scroll = self.tree.verticalScrollBar().value()
        self.tree.setUpdatesEnabled(False)
        self.tree.blockSignals(True)
        self.tree.clear()
        for p in self.procs:
            if self.alerts_only.isChecked() and not p.severity:
                continue
            conns = visible_connections(p, self.show_all.isChecked())
            if not conns and not p.alerts:
                continue
            hosts = {c.raddr: self.resolver.get(c.raddr) for c in conns if c.scope == "internet"}
            if needle:
                proc_text = f"{p.name} {p.exe} {p.pid} {p.user}".lower()
                if needle not in proc_text:
                    conns = [c for c in conns
                             if needle in f"{c.remote} {c.local} {hosts.get(c.raddr, '')}".lower()]
                    if not conns:
                        continue

            key = (p.pid, p.exe or p.name)
            blocked = p.pid in self.blocked_pids
            alert_text = "; ".join((["Blocked from the internet"] if blocked else []) +
                                   [a.message for a in p.alerts])
            n_inet = sum(1 for c in conns if c.scope == "internet")
            item = QTreeWidgetItem([p.name, str(p.pid or ""), p.user, "", "", f"{n_inet} internet",
                                    "", "", "", alert_text])
            item.setData(0, ROLE, key)
            item.setData(1, ROLE, p)
            item.setToolTip(0, "\n".join(filter(None, [p.exe, p.cmdline] +
                                                [f"[{SEVERITY_NAMES[a.severity]}] {a.message}" for a in p.all_alerts()])))
            font = item.font(0)
            font.setBold(True)
            item.setFont(0, font)
            self._color(item, p.severity, blocked)
            for c in conns:
                child = QTreeWidgetItem(["", "", "", c.proto, c.local, c.remote, hosts.get(c.raddr, ""),
                                         c.status, c.scope, "; ".join(a.message for a in c.alerts)])
                child.setData(1, ROLE, c)
                self._color(child, max((a.severity for a in c.alerts), default=0), blocked)
                item.addChild(child)
            self.tree.addTopLevelItem(item)
            # Flagged apps auto-expand the first time they appear; afterwards the user's choice sticks.
            if p.severity and key not in self.auto_expanded:
                self.auto_expanded.add(key)
                self.expanded.add(key)
            item.setExpanded(key in self.expanded)
        self.tree.blockSignals(False)
        self.tree.setUpdatesEnabled(True)
        self.tree.verticalScrollBar().setValue(scroll)

    def populate_blocked(self):
        self.blocked_tree.clear()
        empty = not self.blocked_apps
        self.blocked_tree.setVisible(not empty)
        self.blocked_empty.setVisible(empty)
        self.unblock_all.setVisible(len(self.blocked_apps) > 1)
        now = time.time()
        for app in self.blocked_apps:
            item = QTreeWidgetItem([app["name"], str(len(app["pids"])), ago(now - app["since"]), app["exe"], ""])
            item.setToolTip(1, "PIDs: " + ", ".join(map(str, app["pids"])))
            self.blocked_tree.addTopLevelItem(item)
            button = QPushButton("Unblock")
            button.clicked.connect(lambda _=False, pids=app["pids"]: self.run_helper(["unblock", *map(str, pids)]))
            self.blocked_tree.setItemWidget(item, 4, button)

    @staticmethod
    def _color(item, severity, blocked=False):
        if not severity and not blocked:
            return
        color = QColor(BLOCKED_COLOR if blocked and not severity else SEVERITY_COLORS[severity])
        for col in range(len(COLUMNS)):
            item.setForeground(col, QBrush(color))

    def context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return
        obj = item.data(1, ROLE)
        menu = QMenu(self)
        if hasattr(obj, "connections"):  # a process row
            if obj.pid and obj.pid in self.blocked_pids:
                menu.addAction("Unblock internet access", lambda: self.unblock_app(obj))
            elif obj.pid:
                menu.addAction("Block internet access…", lambda: self.block_app(obj))
            menu.addSeparator()
            if obj.exe:
                menu.addAction("Copy executable path", lambda: QGuiApplication.clipboard().setText(obj.exe))
                menu.addAction("Look up executable on VirusTotal (hash only)", lambda: self.virustotal_file(obj.exe))
            if obj.cmdline:
                menu.addAction("Copy command line", lambda: QGuiApplication.clipboard().setText(obj.cmdline))
            if obj.pid:
                menu.addSeparator()
                menu.addAction(f"Kill {obj.name} (pid {obj.pid})…", lambda: self.kill(obj))
        elif obj.raddr:
            ip = obj.raddr
            menu.addAction(f"Copy {ip}", lambda: QGuiApplication.clipboard().setText(ip))
            menu.addAction("Look up on AbuseIPDB", lambda: self.open_url(f"https://www.abuseipdb.com/check/{ip}"))
            menu.addAction("Look up on VirusTotal", lambda: self.open_url(f"https://www.virustotal.com/gui/ip-address/{ip}"))
            menu.addAction("Look up on Shodan", lambda: self.open_url(f"https://www.shodan.io/host/{ip}"))
        if not menu.isEmpty():
            menu.exec(self.tree.viewport().mapToGlobal(pos))

    # --- actions --------------------------------------------------------------

    def block_app(self, proc):
        if not blockctl.installed():
            QMessageBox.information(
                self, "One-time setup needed",
                "Blocking needs a small helper installed with admin rights. Run this once in a terminal:\n\n"
                f"sudo {SETUP_SCRIPT}")
            return
        pids = same_app_pids(proc)
        answer = QMessageBox.question(
            self, "Block internet access",
            f"Block {proc.name} from the internet?\n\n{proc.exe or proc.name}\n"
            f"{len(pids)} process(es). Its open connections will be closed.\n"
            "You can undo this on the Blocked page.")
        if answer == QMessageBox.Yes:
            self.run_helper(["block", *map(str, pids)])

    def unblock_app(self, proc):
        pids = [p for app in self.blocked_apps if proc.pid in app["pids"] for p in app["pids"]] or [proc.pid]
        self.run_helper(["unblock", *map(str, pids)])

    def run_helper(self, args):
        """Run the privileged helper through pkexec (asks for your password, cached briefly)."""
        if self.helper and self.helper.state() != QProcess.NotRunning:
            return
        self.helper = QProcess(self)
        self.helper.finished.connect(self.helper_done)
        self.helper.start("pkexec", [blockctl.INSTALLED_PATH, *args])

    def helper_done(self, code, _status):
        if code not in (0,):
            err = bytes(self.helper.readAllStandardError()).decode(errors="replace").strip()
            if code in (126, 127) and not err:  # pkexec: dialog dismissed / not authorized
                return
            QMessageBox.warning(self, "NetApp Monitor", err or f"The helper failed (exit code {code}).")
        self.tick()
        self.populate()

    @staticmethod
    def open_url(url):
        QDesktopServices.openUrl(QUrl(url))

    def virustotal_file(self, exe):
        try:
            digest = sha256(exe)
        except OSError as e:
            QMessageBox.warning(self, "NetApp Monitor", f"Could not read {exe}: {e}")
            return
        self.open_url(f"https://www.virustotal.com/gui/file/{digest}")

    def kill(self, proc):
        answer = QMessageBox.question(
            self, "Kill process",
            f"Send SIGTERM to {proc.name} (pid {proc.pid})?\n\n{proc.exe}\n{proc.cmdline[:300]}")
        if answer != QMessageBox.Yes:
            return
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except OSError as e:
            QMessageBox.warning(self, "NetApp Monitor", f"Could not kill pid {proc.pid}: {e}")
        self.tick()

    # --- window / tray --------------------------------------------------------

    def tray_clicked(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.hide() if self.isVisible() and self.isActiveWindow() else self.show_window()

    def show_window(self):
        self.populate()
        self.show()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event):
        if self.has_tray:
            event.ignore()
            self.hide()
        else:
            event.accept()


def main(start_hidden: bool = False, reveal_pid: int | None = None) -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_ID)
    app.setDesktopFileName(APP_ID)
    message = f"reveal {reveal_pid}" if reveal_pid is not None else "show"

    # Single instance: launching again raises the existing dashboard (or jumps to an app).
    probe = QLocalSocket()
    probe.connectToServer(APP_ID)
    if probe.waitForConnected(300):
        probe.write(message.encode())
        probe.waitForBytesWritten(300)
        return 0
    QLocalServer.removeServer(APP_ID)
    server = QLocalServer()
    server.listen(APP_ID)

    has_tray = QSystemTrayIcon.isSystemTrayAvailable()
    app.setQuitOnLastWindowClosed(not has_tray)
    window = Dashboard(has_tray)

    def on_message(text: str):
        if text.startswith("reveal "):
            window.reveal(int(text.split()[1]) or None)
        else:
            window.show_window()

    def on_connection():
        sock = server.nextPendingConnection()
        sock.readyRead.connect(lambda: on_message(bytes(sock.readAll()).decode(errors="replace").strip()))
        sock.disconnected.connect(sock.deleteLater)

    server.newConnection.connect(on_connection)
    if reveal_pid is not None:
        window.reveal(reveal_pid or None)
    elif not (start_hidden and has_tray):
        window.show_window()

    signal.signal(signal.SIGINT, lambda *_: app.quit())
    return app.exec()
