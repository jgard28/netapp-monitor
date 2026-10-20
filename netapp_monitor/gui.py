"""Tray icon plus a dashboard window listing every app's network connections."""
from __future__ import annotations

import hashlib
import os
import signal
import sys
import threading

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QBrush, QColor, QDesktopServices, QGuiApplication, QIcon, QPainter, QPen, QPixmap
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMenu, QMessageBox, QPushButton, QSystemTrayIcon, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from . import intel
from .collector import HIGH, SEVERITY_NAMES, Resolver, snapshot, visible_connections
from .detect import BeaconTracker, analyze

APP_ID = "netapp-monitor"
REFRESH_MS = 3000
SEVERITY_COLORS = {0: "#3fb950", 1: "#d29922", 2: "#f0883e", 3: "#f85149"}
COLUMNS = ["Application / connection", "PID", "User", "Proto", "Local", "Remote", "Host", "State", "Scope", "Alerts"]
ROLE = Qt.UserRole


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


class Dashboard(QMainWindow):
    def __init__(self, has_tray: bool):
        super().__init__()
        self.has_tray = has_tray
        self.setWindowTitle("NetApp Monitor")
        self.resize(1200, 700)
        self.procs = []
        self.blocklist: dict[str, str] = {}
        self.tracker = BeaconTracker()
        self.resolver = Resolver()
        self.expanded: set = set()
        self.auto_expanded: set = set()
        self.notified: set = set()

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

        self.status = QLabel()
        layout = QVBoxLayout()
        layout.addLayout(bar)
        layout.addWidget(self.tree, 1)
        layout.addWidget(self.status)
        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)

        self.tray = QSystemTrayIcon(tray_icon(0), self) if has_tray else None
        if self.tray:
            menu = QMenu()
            menu.addAction("Show dashboard", self.show_window)
            menu.addAction("Refresh threat intel", self.load_intel)
            menu.addSeparator()
            menu.addAction("Quit", QApplication.quit)
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self.tray_clicked)
            self.tray.show()

        self.timer = QTimer(self, interval=REFRESH_MS, timeout=self.tick)
        self.timer.start()
        self.user_list_mtime = intel.user_list_mtime()
        self.load_intel()
        self.tick()

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
        worst = max((p.severity for p in self.procs), default=0)
        flagged = sum(1 for p in self.procs if p.severity)
        internet = sum(len(p.internet) for p in self.procs)
        summary = (f"{len(self.procs)} apps · {internet} internet connections · {flagged} flagged · "
                   f"{len(self.blocklist):,} blocklisted IPs loaded")
        self.status.setText(summary)
        if self.tray:
            self.tray.setIcon(tray_icon(worst))
            self.tray.setToolTip(f"NetApp Monitor\n{summary}")
            self.notify()
        if self.isVisible() and self.live.isChecked():
            self.populate()

    def notify(self):
        for p in self.procs:
            for a in p.all_alerts():
                key = (p.exe or p.name, a.message)
                if a.severity >= HIGH and key not in self.notified:
                    self.notified.add(key)
                    self.tray.showMessage(f"Suspicious: {p.name} (pid {p.pid})", a.message,
                                          QSystemTrayIcon.Critical, 10000)

    # --- view -----------------------------------------------------------------

    def populate(self):
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
            alert_text = "; ".join(a.message for a in p.alerts)
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
            self._color(item, p.severity)
            for c in conns:
                child = QTreeWidgetItem(["", "", "", c.proto, c.local, c.remote, hosts.get(c.raddr, ""),
                                         c.status, c.scope, "; ".join(a.message for a in c.alerts)])
                child.setData(1, ROLE, c)
                self._color(child, max((a.severity for a in c.alerts), default=0))
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

    @staticmethod
    def _color(item, severity):
        if not severity:
            return
        color = QColor(SEVERITY_COLORS[severity])
        for col in range(len(COLUMNS)):
            item.setForeground(col, QBrush(color))

    def context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return
        obj = item.data(1, ROLE)
        menu = QMenu(self)
        if hasattr(obj, "connections"):  # a process row
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


def main(start_hidden: bool = False) -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_ID)
    app.setDesktopFileName(APP_ID)

    # Single instance: launching again just raises the existing dashboard.
    probe = QLocalSocket()
    probe.connectToServer(APP_ID)
    if probe.waitForConnected(300):
        probe.write(b"show")
        probe.waitForBytesWritten(300)
        return 0
    QLocalServer.removeServer(APP_ID)
    server = QLocalServer()
    server.listen(APP_ID)

    has_tray = QSystemTrayIcon.isSystemTrayAvailable()
    app.setQuitOnLastWindowClosed(not has_tray)
    window = Dashboard(has_tray)
    server.newConnection.connect(lambda: (server.nextPendingConnection(), window.show_window()))
    if not (start_hidden and has_tray):
        window.show_window()

    signal.signal(signal.SIGINT, lambda *_: app.quit())
    return app.exec()
