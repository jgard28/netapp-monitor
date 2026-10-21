"""Tray icon plus a dashboard window listing every app's network connections."""
from __future__ import annotations

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
    QApplication, QButtonGroup, QCheckBox, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMenu, QMessageBox, QPushButton, QSplitter, QStackedWidget, QSystemTrayIcon, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from . import blockctl, intel
from .appinfo import AppInfoLoader, sha256
from .collector import (HIGH, MEDIUM, SEVERITY_COLORS, SEVERITY_NAMES, Resolver, Traffic, human_bytes, rate_text,
                        severity_of, snapshot, visible_connections)
from .detect import INTERPRETER, SHELLS, BeaconTracker, analyze
from .dns import DnsWatcher
from .explain import explain
from .geo import GeoDB
from .history import History
from .memory import Baseline, Trust
from .notifier import Notifier
from .panel import DetailPanel

APP_ID = "netapp-monitor"
REFRESH_MS = 3000
INTEL_REFRESH_MS = 30 * 60 * 1000  # each feed only re-downloads once its cache is stale
POPUP_TIMEOUT_MS = {HIGH: 20000, MEDIUM: 12000}  # pop-ups close themselves after this
POPUP_BATCH = 3  # more new alerts than this in one refresh become a single summary pop-up
BLOCKED_COLOR = "#8b949e"  # also used for muted (trusted) alerts
NEW_COLOR = "#58a6ff"
COLUMNS = ["Application / connection", "Alerts", "Traffic", "PID", "User", "Proto", "Local", "Remote", "Host",
           "Network", "State", "Scope"]
ROLE = Qt.UserRole
PAGE_CONNECTIONS, PAGE_HISTORY, PAGE_BLOCKED, PAGE_TRUSTED = range(4)
HISTORY_RANGES = [("Last hour", 3600), ("Last 24 hours", 86400), ("Last 7 days", 7 * 86400),
                  ("Last 30 days", 30 * 86400)]
SETUP_SCRIPT = Path(__file__).resolve().parent.parent / "install-system.sh"
DNS_STATUS = {"starting": "DNS: connecting…", "watching": "DNS: watching lookups",
              "needs-setup": f"DNS: off (run sudo {SETUP_SCRIPT} once)", "unavailable": "DNS: unavailable"}


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


def ago(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"


def when(ts: float) -> str:
    """'14:32' today, 'Oct 18 14:32' otherwise."""
    t = time.localtime(ts)
    return time.strftime("%H:%M" if t[:3] == time.localtime()[:3] else "%b %d %H:%M", t)


def owner_text(owner) -> str:
    return owner.label() if owner else ""


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
        self.always: dict[str, dict] = {}  # program path -> info, blocked whenever it runs
        self.tracker = BeaconTracker()
        self.trust = Trust()
        self.loader = AppInfoLoader()
        self.dns = DnsWatcher()
        self.baseline = Baseline()
        self.resolver = Resolver()
        self.geo = GeoDB()
        self.traffic = Traffic()
        self.history = History()
        self.expanded: set = set()
        self.auto_expanded: set = set()
        self.notified: set = set()
        self.helper: QProcess | None = None
        self.selected = None  # (pid, exe) of the app shown in the detail panel

        # View switcher: Connections | History | Blocked | Trusted
        self.conn_tab = QPushButton("Connections", checkable=True, checked=True)
        self.history_tab = QPushButton("History", checkable=True)
        self.block_tab = QPushButton("Blocked", checkable=True)
        self.trust_tab = QPushButton("Trusted", checkable=True)
        self.tabs = (self.conn_tab, self.history_tab, self.block_tab, self.trust_tab)
        group = QButtonGroup(self)
        group.setExclusive(True)
        switcher = QHBoxLayout()
        for i, b in enumerate(self.tabs):
            b.setFlat(True)
            group.addButton(b, i)
            switcher.addWidget(b)
        group.idClicked.connect(self.switch_page)
        switcher.addStretch(1)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._connections_page())
        self.pages.addWidget(self._history_page())
        self.pages.addWidget(self._blocked_page())
        self.pages.addWidget(self._trusted_page())

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
        self.new_only = QCheckBox("New only")
        self.new_only.setToolTip("Apps and destinations first seen in the last 24 hours")
        self.live = QCheckBox("Live", checked=True)
        refresh = QPushButton("Refresh")
        for w in (self.search, self.show_all, self.alerts_only, self.new_only):
            (w.textChanged if w is self.search else w.toggled).connect(self.populate)
        refresh.clicked.connect(self.tick)

        bar = QHBoxLayout()
        bar.addWidget(self.search, 1)
        for w in (self.show_all, self.alerts_only, self.new_only, self.live, refresh):
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
        for col, width in enumerate((230, 380, 170, 70, 70, 50, 180, 190, 220, 230, 100)):
            self.tree.setColumnWidth(col, width)
        header.setStretchLastSection(True)
        self.tree.currentItemChanged.connect(self.select_item)

        self.details = DetailPanel(self)
        self.details.hide()
        splitter = QSplitter()
        splitter.addWidget(self.tree)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([800, 420])

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(bar)
        layout.addWidget(splitter, 1)
        return page

    def _history_page(self):
        self.history_search = QLineEdit(placeholderText="Filter by app, IP, domain or network…")
        self.history_range = QComboBox()
        for label, _ in HISTORY_RANGES:
            self.history_range.addItem(label)
        self.history_range.setCurrentIndex(1)
        self.history_dest_btn = QPushButton("Destinations", checkable=True, checked=True)
        self.history_alert_btn = QPushButton("Alerts", checkable=True)
        group = QButtonGroup(self)
        group.setExclusive(True)
        for b in (self.history_dest_btn, self.history_alert_btn):
            b.setFlat(True)
            group.addButton(b)
        refresh = QPushButton("Refresh")
        self.history_search.textChanged.connect(self.populate_history)
        self.history_range.currentIndexChanged.connect(self.populate_history)
        group.buttonClicked.connect(self.populate_history)
        refresh.clicked.connect(self.populate_history)
        bar = QHBoxLayout()
        bar.addWidget(self.history_search, 1)
        for w in (self.history_range, self.history_dest_btn, self.history_alert_btn, refresh):
            bar.addWidget(w)

        self.history_dests = QTreeWidget()
        self.history_dests.setHeaderLabels(["Application / destination", "Host", "Network", "Connections",
                                            "First seen", "Last seen", "Data", "Alerts"])
        self.history_dests.setUniformRowHeights(True)
        self.history_dests.setAlternatingRowColors(True)
        for col, width in enumerate((260, 240, 240, 100, 110, 110, 150)):
            self.history_dests.setColumnWidth(col, width)
        self.history_alerts = QTreeWidget()
        self.history_alerts.setHeaderLabels(["Time", "Severity", "Application", "Alert", "Remote", "Host"])
        self.history_alerts.setRootIsDecorated(False)
        self.history_alerts.setUniformRowHeights(True)
        self.history_alerts.setAlternatingRowColors(True)
        for col, width in enumerate((110, 80, 180, 520, 190)):
            self.history_alerts.setColumnWidth(col, width)
        for tree in (self.history_dests, self.history_alerts):
            tree.setContextMenuPolicy(Qt.CustomContextMenu)
            tree.customContextMenuRequested.connect(lambda pos, t=tree: self.history_menu(t, pos))
        self.history_empty = QLabel()
        self.history_empty.setAlignment(Qt.AlignCenter)
        self.history_views = QStackedWidget()
        for w in (self.history_dests, self.history_alerts, self.history_empty):
            self.history_views.addWidget(w)

        note = QLabel(f"Internet connections and alerts are kept for 30 days in {self.history.path}. "
                      "Nothing leaves your computer.")
        note.setStyleSheet(f"color: {BLOCKED_COLOR}")
        note.setWordWrap(True)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(bar)
        layout.addWidget(self.history_views, 1)
        layout.addWidget(note)
        return page

    def _blocked_page(self):
        intro = QLabel("These apps can't reach the internet or your LAN (loopback still works). "
                       "“Until it exits” blocks end when the app closes; “Always” blocks apply every "
                       "time the program starts, also after a reboot, until you unblock it.")
        intro.setWordWrap(True)
        self.unblock_all = QPushButton("Unblock all")
        self.unblock_all.clicked.connect(lambda: self.run_helper(["unblock", "--all"]))
        top = QHBoxLayout()
        top.addWidget(intro, 1)
        top.addWidget(self.unblock_all)

        self.blocked_tree = QTreeWidget()
        self.blocked_tree.setHeaderLabels(["Application", "Block", "Processes", "Blocked for", "Path", ""])
        self.blocked_tree.setRootIsDecorated(False)
        for col, width in enumerate((220, 110, 100, 110, 480, 110)):
            self.blocked_tree.setColumnWidth(col, width)
        self.blocked_tree.header().setStretchLastSection(False)
        self.blocked_tree.header().setSectionResizeMode(4, QHeaderView.Stretch)
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

    def _trusted_page(self):
        intro = QLabel("Alerts from trusted apps and destinations are muted: still listed, greyed out, "
                       "with no pop-ups. Known C2 servers from threat intel always alert.")
        intro.setWordWrap(True)
        self.trusted_tree = QTreeWidget()
        self.trusted_tree.setHeaderLabels(["Trusted", "Type", "Since", "Details", ""])
        self.trusted_tree.setRootIsDecorated(False)
        for col, width in enumerate((220, 100, 110, 520, 110)):
            self.trusted_tree.setColumnWidth(col, width)
        self.trusted_tree.header().setStretchLastSection(False)
        self.trusted_tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self.trusted_empty = QLabel("Nothing is trusted yet.\n\nIf an app or destination keeps raising alerts "
                                    "you know are fine, right-click it on the Connections page and choose "
                                    "“Trust this app” or “Trust this destination”.")
        self.trusted_empty.setAlignment(Qt.AlignCenter)
        self.trusted_empty.setWordWrap(True)

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(intro)
        layout.addWidget(self.trusted_tree, 1)
        layout.addWidget(self.trusted_empty, 1)
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
        self.procs = analyze(snapshot(), self.blocklist, self.tracker, self.trust, self.baseline, self.loader,
                             self.dns, self.geo, self.traffic)
        try:
            self.history.record(self.procs)
        except Exception as e:  # a full disk or locked database must not stop monitoring
            print(f"netapp-monitor: history not saved: {e}", file=sys.stderr)
        self.refresh_blocked()
        self.trust_tab.setText(f"Trusted ({len(self.trust)})" if len(self.trust) else "Trusted")
        worst = max((p.severity for p in self.procs), default=0)
        flagged = sum(1 for p in self.procs if p.severity)
        new = sum(1 for p in self.procs if p.has_new)
        internet = sum(len(p.internet) for p in self.procs)
        learning = self.baseline.learning_left()
        new_text = f"learning normal traffic, {ago(learning)} left" if learning else f"{new} new"
        up = sum(c.up for p in self.procs for c in p.internet)
        down = sum(c.down for p in self.procs for c in p.internet)
        summary = (f"{len(self.procs)} apps · {internet} internet connections · "
                   f"↑ {human_bytes(up)}/s ↓ {human_bytes(down)}/s · {flagged} flagged · "
                   f"{new_text} · {len(self.blocked_apps)} blocked · {DNS_STATUS[self.dns.status]} · "
                   f"intel: {self.blocklist.summary() or 'loading…'}")
        self.status.setText(summary)
        if self.tray:
            self.tray.setIcon(tray_icon(worst))
            self.tray.setToolTip(self.tray_summary(worst, flagged, new, internet, up, down, learning))
            self.notify()
        if self.isVisible() and self.live.isChecked():
            self.populate()

    def tray_summary(self, worst, flagged, new, internet, up, down, learning) -> str:
        """A short hover card: the verdict first, then a few key numbers, one per line."""
        if flagged:
            verdict = f"⚠ {flagged} app{'s' if flagged != 1 else ''} flagged ({SEVERITY_NAMES[worst]})"
        else:
            verdict = "✔ All clear"
        lines = ["NetApp Monitor", verdict, f"{internet} internet connection{'s' if internet != 1 else ''}",
                 f"↑ {human_bytes(up)}/s   ↓ {human_bytes(down)}/s"]
        if learning:
            lines.append(f"Learning normal traffic ({ago(learning)} left)")
        elif new:
            lines.append(f"{new} new")
        if self.blocked_apps:
            lines.append(f"{len(self.blocked_apps)} blocked")
        if self.dns.status != "watching":
            lines.append("DNS matching off")
        return "\n".join(lines)

    def refresh_blocked(self):
        self.blocked_pids = blockctl.blocked_pids()
        self.always = blockctl.always_blocked()
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
        self.blocked_apps = list(apps.values())
        for exe, info in self.always.items():
            app = apps.get(exe)
            if app is None:  # always blocked, but not running right now
                self.blocked_apps.append({"name": os.path.basename(exe), "exe": exe, "pids": [],
                                          "since": info.get("since", time.time())})
        self.blocked_apps.sort(key=lambda a: a["name"].lower())
        self.block_tab.setText(f"Blocked ({len(self.blocked_apps)})" if self.blocked_apps else "Blocked")

    def notify(self):
        """Pop up each high/medium alert once per session, batching bursts into one summary."""
        fresh = []
        for p in self.procs:
            for a in p.all_alerts():
                # Ignore numbers like the beacon interval so a drifting value doesn't re-alert.
                key = (p.exe or p.name, re.sub(r"~\d+s", "", a.message))
                if a.severity >= MEDIUM and not a.muted and key not in self.notified:
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
            why = explain(a.topic)
            body = f"{a.message}\n{why.short}" if why else a.message
            self.popup(f"{label}: {p.name} (pid {p.pid})", body, a.severity, p.pid)

    def popup(self, title, body, severity, pid):
        timeout = POPUP_TIMEOUT_MS[severity]
        if self.notifier.available:
            self.notifier.send(title, body, timeout, pid)
        else:
            icon = QSystemTrayIcon.Critical if severity >= HIGH else QSystemTrayIcon.Warning
            self.tray.showMessage(title, body, icon, timeout)

    def reveal(self, pid):
        """Open the dashboard on the Connections page with the alerted app selected."""
        self.switch_page(PAGE_CONNECTIONS)
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
        self.tabs[index].setChecked(True)
        self.pages.setCurrentIndex(index)
        if index == PAGE_HISTORY:
            self.populate_history()
        self.populate()

    def show_history(self, needle: str):
        self.history_search.setText(needle)
        self.switch_page(PAGE_HISTORY)

    def populate(self):
        page = self.pages.currentIndex()
        if page == PAGE_HISTORY:
            return  # refreshed on demand, so the list doesn't jump while you read it
        if page == PAGE_BLOCKED:
            self.populate_blocked()
            return
        if page == PAGE_TRUSTED:
            self.populate_trusted()
            return
        needle = self.search.text().strip().lower()
        scroll = self.tree.verticalScrollBar().value()
        self.tree.setUpdatesEnabled(False)
        self.tree.blockSignals(True)
        self.tree.clear()
        for p in self.procs:
            if self.alerts_only.isChecked() and not p.severity:
                continue
            if self.new_only.isChecked() and not p.has_new:
                continue
            conns = visible_connections(p, self.show_all.isChecked())
            if self.new_only.isChecked() and not p.new:
                conns = [c for c in conns if c.new]
            if not conns and not p.alerts:
                continue
            # Prefer the name the app actually looked up; reverse DNS is the fallback.
            hosts = {c.raddr: c.domain or self.resolver.get(c.raddr) for c in conns if c.scope == "internet"}
            if needle:
                proc_text = f"{p.name} {p.exe} {p.pid} {p.user}".lower()
                if needle not in proc_text:
                    conns = [c for c in conns
                             if needle in f"{c.remote} {c.local} {hosts.get(c.raddr, '')}".lower()]
                    if not conns:
                        continue

            key = (p.pid, p.exe or p.name)
            blocked = p.pid in self.blocked_pids
            tags = (["Blocked from the internet"] if blocked else []) + \
                   (["New: first time online"] if p.new else []) + \
                   (["Trusted app"] if p.exe and p.exe in self.trust.apps else [])
            alert_text = "; ".join(tags + [self._alert_text(a) for a in p.alerts])
            n_inet = sum(1 for c in conns if c.scope == "internet")
            item = QTreeWidgetItem([p.name, alert_text, rate_text(p.up, p.down), str(p.pid or ""), p.user, "", "",
                                    f"{n_inet} internet", "", "", "", ""])
            item.setData(0, ROLE, key)
            item.setData(1, ROLE, p)
            item.setToolTip(0, "\n".join(filter(None, [p.exe, p.cmdline] +
                                                [f"[{SEVERITY_NAMES[a.severity]}] {a.message}" for a in p.all_alerts()])))
            item.setToolTip(1, self._alert_tooltip(p.alerts))
            font = item.font(0)
            font.setBold(True)
            item.setFont(0, font)
            self._color(item, p.severity, blocked, p.has_new, any(a.muted for a in p.alerts))
            for c in conns:
                ctags = (["New destination"] if c.new and not p.new else []) + \
                        (["Trusted destination"] if c.raddr in self.trust.destinations else [])
                child = QTreeWidgetItem(["", "; ".join(ctags + [self._alert_text(a) for a in c.alerts]),
                                         rate_text(c.up, c.down), "", "", c.proto, c.local, c.remote,
                                         hosts.get(c.raddr, ""), owner_text(c.owner), c.status, c.scope])
                child.setData(1, ROLE, c)
                child.setToolTip(1, self._alert_tooltip(c.alerts))
                if c.sent or c.received:
                    child.setToolTip(2, f"So far on this connection: ↑ {human_bytes(c.sent)} ↓ {human_bytes(c.received)}")
                if c.owner:
                    child.setToolTip(9, f"AS{c.owner.asn} {c.owner.org}" + (
                        "\nA rented server (VPS / hosting). Normal for many websites, but also where "
                        "most malware servers live." if c.owner.hosting else ""))
                self._color(child, severity_of(c.alerts), blocked, c.new, any(a.muted for a in c.alerts))
                item.addChild(child)
            self.tree.addTopLevelItem(item)
            # Flagged apps auto-expand the first time they appear; afterwards the user's choice sticks.
            if p.severity and key not in self.auto_expanded:
                self.auto_expanded.add(key)
                self.expanded.add(key)
            item.setExpanded(key in self.expanded)
            if key == self.selected:
                self.tree.setCurrentItem(item)
                self.details.show_process(p)
        self.tree.blockSignals(False)
        self.tree.setUpdatesEnabled(True)
        self.tree.verticalScrollBar().setValue(scroll)

    def select_item(self, item, _previous=None):
        if item is None:
            return
        proc = (item.parent() or item).data(1, ROLE)
        self.selected = (proc.pid, proc.exe or proc.name)
        self.details.show_process(proc)
        self.details.show()

    def close_details(self):
        self.selected = None
        self.details.hide()
        self.tree.blockSignals(True)
        self.tree.setCurrentItem(None)
        self.tree.blockSignals(False)

    def populate_blocked(self):
        self.blocked_tree.clear()
        empty = not self.blocked_apps
        self.blocked_tree.setVisible(not empty)
        self.blocked_empty.setVisible(empty)
        self.unblock_all.setVisible(len(self.blocked_apps) > 1)
        now = time.time()
        for app in self.blocked_apps:
            always = app["exe"] in self.always
            running = str(len(app["pids"])) if app["pids"] else "not running"
            item = QTreeWidgetItem([app["name"], "Always" if always else "Until it exits", running,
                                    ago(now - app["since"]), app["exe"], ""])
            item.setToolTip(1, "Blocked every time this program starts, also after a reboot" if always
                            else "The block ends when the app exits")
            item.setToolTip(2, "PIDs: " + ", ".join(map(str, app["pids"])) if app["pids"]
                            else "Will be blocked as soon as it starts")
            self.blocked_tree.addTopLevelItem(item)
            button = QPushButton("Unblock")
            args = ["unblock-exe", app["exe"]] if always else ["unblock", *map(str, app["pids"])]
            button.clicked.connect(lambda _=False, a=args: self.run_helper(a))
            self.blocked_tree.setItemWidget(item, 5, button)

    def populate_history(self):
        since = time.time() - HISTORY_RANGES[self.history_range.currentIndex()][1]
        needle = self.history_search.text().strip()
        if self.history_alert_btn.isChecked():
            rows = self.history.alerts(since, needle)
            tree = self.history_alerts
            tree.clear()
            for r in rows:
                remote = f"{r['raddr']}:{r['rport']}" if r["raddr"] else ""
                item = QTreeWidgetItem([when(r["time"]), SEVERITY_NAMES[r["severity"]], r["name"],
                                        ("(muted) " if r["muted"] else "") + r["message"], remote, r["domain"] or ""])
                why = explain(r["topic"] or "")
                item.setToolTip(3, f"{r['message']}\n\n{why.short}" if why else r["message"])
                item.setToolTip(2, r["app"])
                color = BLOCKED_COLOR if r["muted"] else SEVERITY_COLORS[r["severity"]]
                for col in range(6):
                    item.setForeground(col, QBrush(QColor(color)))
                item.setData(0, ROLE, r)
                tree.addTopLevelItem(item)
            empty_text = "No alerts in this period."
        else:
            rows = self.history.destinations(since, needle)
            tree = self.history_dests
            open_apps = {tree.topLevelItem(i).data(0, ROLE) for i in range(tree.topLevelItemCount())
                         if tree.topLevelItem(i).isExpanded()}
            tree.clear()
            apps: dict[str, QTreeWidgetItem] = {}
            for r in rows:
                parent = apps.get(r["app"])
                if parent is None:
                    parent = apps[r["app"]] = QTreeWidgetItem([r["name"]] + [""] * 7)
                    parent.setData(0, ROLE, r["app"])
                    parent.setToolTip(0, r["app"])
                    font = parent.font(0)
                    font.setBold(True)
                    parent.setFont(0, font)
                    parent.worst, parent.count = 0, 0
                    tree.addTopLevelItem(parent)
                owner = (f"{r['country']} · {r['owner']}" if r["country"] else r["owner"]) or ""
                child = QTreeWidgetItem([
                    f"{r['raddr']}:{r['rport']}", r["domain"] or self.resolver.get(r["raddr"]), owner,
                    str(r["count"]), when(r["first"]), when(r["last"]),
                    f"↑ {human_bytes(r['sent'] or 0)}  ↓ {human_bytes(r['received'] or 0)}" if r["sent"] or r["received"]
                    else "", r["alerts"] or ""])
                child.setData(0, ROLE, r)
                if r["severity"]:
                    for col in range(8):
                        child.setForeground(col, QBrush(QColor(SEVERITY_COLORS[r["severity"]])))
                parent.addChild(child)
                parent.worst = max(parent.worst, r["severity"] or 0)
                parent.count += 1
            for app, parent in apps.items():
                parent.setText(1, f"{parent.count} destination{'s' if parent.count != 1 else ''}")
                if parent.worst:
                    parent.setForeground(0, QBrush(QColor(SEVERITY_COLORS[parent.worst])))
                parent.setExpanded(app in open_apps or len(apps) == 1)
            empty_text = "No internet connections recorded in this period."
        if needle:
            empty_text += f"\nNothing matches “{needle}”."
        self.history_empty.setText(empty_text)
        self.history_views.setCurrentWidget(tree if rows else self.history_empty)

    def history_menu(self, tree, pos):
        item = tree.itemAt(pos)
        row = item.data(0, ROLE) if item else None
        if not isinstance(row, dict) or not row.get("raddr"):
            return
        ip = row["raddr"]
        menu = QMenu(self)
        menu.addAction(f"Copy {ip}", lambda: QGuiApplication.clipboard().setText(ip))
        menu.addAction("Look up on AbuseIPDB", lambda: self.open_url(f"https://www.abuseipdb.com/check/{ip}"))
        menu.addAction("Look up on VirusTotal", lambda: self.open_url(f"https://www.virustotal.com/gui/ip-address/{ip}"))
        menu.exec(tree.viewport().mapToGlobal(pos))

    def populate_trusted(self):
        self.trusted_tree.clear()
        rows = [("app", exe, since) for exe, since in self.trust.apps.items()] + \
               [("destination", ip, since) for ip, since in self.trust.destinations.items()]
        self.trusted_tree.setVisible(bool(rows))
        self.trusted_empty.setVisible(not rows)
        now = time.time()
        for kind, key, since in sorted(rows, key=lambda r: -r[2]):
            if kind == "app":
                values = [os.path.basename(key), "App", ago(now - since), key]
            else:
                values = [key, "Destination", ago(now - since), self.resolver.get(key) or "any app, this IP"]
            item = QTreeWidgetItem(values + [""])
            self.trusted_tree.addTopLevelItem(item)
            button = QPushButton("Remove")
            button.setToolTip("Stop trusting; its alerts come back")
            button.clicked.connect(lambda _=False, k=kind, v=key: self.set_trust(k, v, False))
            self.trusted_tree.setItemWidget(item, 4, button)

    @staticmethod
    def _alert_tooltip(alerts) -> str:
        lines = []
        for a in alerts:
            why = explain(a.topic)
            lines.append(f"{a.message}\n  → {why.short}" if why else a.message)
        return "\n".join(lines) + ("\n\nSelect the app for details." if lines else "")

    @staticmethod
    def _alert_text(alert):
        return f"(muted) {alert.message}" if alert.muted else alert.message

    @staticmethod
    def _color(item, severity, blocked=False, new=False, muted=False):
        if muted and not severity:
            item.setForeground(1, QBrush(QColor(BLOCKED_COLOR)))
        if severity:
            color = SEVERITY_COLORS[severity]
        elif blocked:
            color = BLOCKED_COLOR
        elif new:
            color = NEW_COLOR
        else:
            return
        for col in range(len(COLUMNS)):
            item.setForeground(col, QBrush(QColor(color)))

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
            if obj.exe in self.trust.apps:
                menu.addAction("Stop trusting this app", lambda: self.set_trust("app", obj.exe, False))
            elif obj.exe:
                menu.addAction("Trust this app (mute its alerts)", lambda: self.set_trust("app", obj.exe, True))
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
            if ip in self.trust.destinations:
                menu.addAction(f"Stop trusting {ip}", lambda: self.set_trust("destination", ip, False))
            else:
                menu.addAction(f"Trust this destination ({ip})", lambda: self.set_trust("destination", ip, True))
            menu.addSeparator()
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
        box = QMessageBox(QMessageBox.Question, "Block internet access",
                          f"Block {proc.name} from the internet?\n\n{proc.exe or proc.name}\n"
                          f"{len(pids)} process(es). Its open connections will be closed.\n"
                          "You can undo this on the Blocked page.",
                          QMessageBox.Yes | QMessageBox.No, self)
        always = QCheckBox("Always block this program (also after it restarts or the computer reboots)")
        base = os.path.basename(proc.exe or "")
        if not proc.exe:
            always.setEnabled(False)
        elif not blockctl.daemon_installed():
            always.setEnabled(False)
            always.setToolTip(f"Needs the always-block service: run sudo {SETUP_SCRIPT} once more")
        elif base in SHELLS or INTERPRETER.match(base):
            box.setInformativeText(f"Note: {base} runs many different scripts. “Always block” would cut off "
                                   f"every {base} program on this computer, not just this one.")
        box.setCheckBox(always)
        if box.exec() == QMessageBox.Yes:
            self.run_helper(["block", *(["--always"] if always.isChecked() else []), *map(str, pids)])

    def set_trust(self, kind, key, trusted):
        (self.trust.set_app if kind == "app" else self.trust.set_destination)(key, trusted)
        self.tick()
        self.populate()

    def unblock_app(self, proc):
        if proc.exe in self.always:
            self.run_helper(["unblock-exe", proc.exe])
            return
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
    app.aboutToQuit.connect(window.baseline.save)
    app.aboutToQuit.connect(window.history.close)
    if reveal_pid is not None:
        window.reveal(reveal_pid or None)
    elif not (start_hidden and has_tray):
        window.show_window()

    signal.signal(signal.SIGINT, lambda *_: app.quit())
    return app.exec()
