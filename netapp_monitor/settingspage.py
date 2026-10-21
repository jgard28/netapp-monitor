"""The Settings page: every switch in one place, each saying in plain words what it does and
what (if anything) leaves your computer. Features that need admin setup show their status and
the exact command to run, instead of a switch that couldn't work."""
from __future__ import annotations

import html

from PySide6.QtCore import Property, QEasingCurve, QPropertyAnimation, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication, QPainter
from PySide6.QtWidgets import (
    QAbstractButton, QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from . import blockctl

OK_COLOR, OFF_COLOR, WARN_COLOR, MUTED_COLOR = "#3fb950", "#8b949e", "#d29922", "#8b949e"


class Switch(QAbstractButton):
    """An on/off switch: a pill with a sliding knob, keyboard-accessible like a checkbox."""

    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setChecked(checked)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self._pos = 1.0 if checked else 0.0
        self._anim = QPropertyAnimation(self, b"knob", self, duration=120, easingCurve=QEasingCurve.InOutQuad)
        self.toggled.connect(self._slide)

    def sizeHint(self):
        return QSize(44, 24)

    def _slide(self, on):
        self._anim.stop()
        self._anim.setEndValue(1.0 if on else 0.0)
        self._anim.start()

    def get_knob(self):
        return self._pos

    def set_knob(self, value):
        self._pos = value
        self.update()

    knob = Property(float, get_knob, set_knob)

    def setChecked(self, on):  # noqa: N802 (Qt naming)
        super().setChecked(on)
        self._pos = 1.0 if on else 0.0
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(1, 1, self.width() - 2, self.height() - 2)
        on = self.palette().highlight().color()
        track = QColor(on) if self.isChecked() else QColor("#8b949e")  # grey that reads on light and dark
        if not self.isEnabled():
            track.setAlpha(90)
        p.setPen(Qt.NoPen)
        p.setBrush(track)
        p.drawRoundedRect(r, r.height() / 2, r.height() / 2)
        d = r.height() - 6
        x = r.left() + 3 + self._pos * (r.width() - d - 6)
        p.setBrush(QColor("#ffffff"))
        p.drawEllipse(QRectF(x, r.top() + 3, d, d))
        if self.hasFocus():
            p.setPen(self.palette().highlight().color())
            p.setBrush(Qt.NoBrush)
            p.drawRoundedRect(r.adjusted(-1, -1, 1, 1), r.height() / 2, r.height() / 2)


def _label(text="", muted=False, bold=False):
    label = QLabel(text)
    label.setWordWrap(True)
    label.setTextFormat(Qt.RichText)
    label.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse)
    style = []
    if muted:
        style.append(f"color: {MUTED_COLOR}")
    if bold:
        style.append("font-weight: bold")
    label.setStyleSheet("; ".join(style))
    return label


class SettingRow(QFrame):
    """Title and explanation on the left, switch on the right; clicking the text toggles too."""

    toggled = Signal(bool)

    def __init__(self, title, description, checked):
        super().__init__()
        self.switch = Switch(checked)
        self.switch.setAccessibleName(title)
        self.switch.toggled.connect(self.toggled)
        self.state = QLabel()
        self.state.setMinimumWidth(24)
        self.state.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.switch.toggled.connect(self._show_state)
        self._show_state(checked)
        self.title = _label(html.escape(title), bold=True)
        self.description = _label(description, muted=True)
        self.note = _label()
        self.note.hide()
        text = QVBoxLayout()
        text.setSpacing(2)
        text.addWidget(self.title)
        text.addWidget(self.description)
        text.addWidget(self.note)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 6, 0, 6)
        row.addLayout(text, 1)
        row.addSpacing(16)
        row.addWidget(self.state, 0, Qt.AlignTop)
        row.addWidget(self.switch, 0, Qt.AlignTop)

    def _show_state(self, on):
        self.state.setText(f"<span style='color:{OK_COLOR if on else MUTED_COLOR}'>{'On' if on else 'Off'}</span>")

    def mousePressEvent(self, event):  # noqa: N802
        if self.switch.isEnabled() and event.button() == Qt.LeftButton:
            self.switch.toggle()

    def set_note(self, text, color=WARN_COLOR):
        self.note.setText(f"<span style='color:{color}'>{text}</span>" if text else "")
        self.note.setVisible(bool(text))


class FeatureRow(QFrame):
    """A system feature: name, a status dot and line, what it does, and how to set it up."""

    def __init__(self, title, description):
        super().__init__()
        self.title = _label(html.escape(title), bold=True)
        self.status = _label()
        self.description = _label(description, muted=True)
        self.detail = _label()
        self.command = QLabel()
        self.command.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.command.setStyleSheet("font-family: monospace; padding: 4px 8px; border: 1px solid palette(mid);"
                                   " border-radius: 4px;")
        self.copy = QPushButton("Copy")
        self.copy.setToolTip("Copy the command, then paste it in a terminal")
        self.copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.command.text()))
        self.setup = QWidget()
        setup = QHBoxLayout(self.setup)
        setup.setContentsMargins(0, 2, 0, 0)
        setup.addWidget(self.command, 1)
        setup.addWidget(self.copy)
        self.title.setWordWrap(False)
        head = QHBoxLayout()
        head.addWidget(self.title)
        head.addSpacing(8)
        head.addWidget(self.status, 1)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 6, 0, 6)
        layout.setSpacing(2)
        layout.addLayout(head)
        layout.addWidget(self.description)
        layout.addWidget(self.detail)
        layout.addWidget(self.setup)

    def show_state(self, on: bool, text: str, detail: str = "", command: str = "", color: str | None = None):
        dot = "●" if on else "○"
        self.status.setText(f"<span style='color:{color or (OK_COLOR if on else OFF_COLOR)}'>{dot} "
                            f"{html.escape(text)}</span>")
        self.detail.setText(detail)
        self.detail.setVisible(bool(detail))
        self.command.setText(command)
        self.setup.setVisible(bool(command))


def section(title, intro=""):
    box = QVBoxLayout()
    box.setSpacing(2)
    heading = QLabel(html.escape(title))
    heading.setStyleSheet("font-size: 13pt; font-weight: bold; margin-top: 14px;")
    box.addWidget(heading)
    if intro:
        box.addWidget(_label(intro, muted=True))
    return box


def divider():
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setStyleSheet("color: palette(mid);")
    return line


class SettingsPage(QScrollArea):
    def __init__(self, dash, setup_script):
        super().__init__()
        self.dash = dash
        self.script = setup_script
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)

        body = QWidget()
        body.setMaximumWidth(780)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(4, 0, 12, 12)

        alerts = section("Alerts")
        self.popups = SettingRow("Pop-up alerts",
                                 "Show a pop-up for new medium and high alerts. They close on their own after "
                                 "a few seconds, or click one to jump to the app.", dash.popups_enabled)
        self.popups.toggled.connect(dash.set_popups)
        alerts.addWidget(self.popups)
        layout.addLayout(alerts)

        privacy = section("Lookups that leave your computer",
                          "Off unless you turn them on. Each one says exactly what it sends.")
        self.domain_age = SettingRow(
            "Check how old domains are",
            "Flags domains registered in the last few weeks, which is common for phishing and malware sites. "
            "To find out, it asks each domain’s registry (for .com, Verisign) when it was registered. "
            "<b>Sends:</b> the domain name only, e.g. example.com, once per domain.", dash.ages.enabled)
        self.domain_age.toggled.connect(dash.set_domain_age)
        privacy.addWidget(self.domain_age)
        privacy.addWidget(divider())
        privacy.addWidget(_label(
            "<b>Always on, and nothing about you is sent:</b><br>"
            "• Threat-intel lists (ThreatFox, Feodo Tracker, IPsum) are downloaded every few hours.<br>"
            "• The IP owner database (iptoasn.com) is downloaded weekly; every lookup happens on this computer.<br>"
            "• VirusTotal, AbuseIPDB and Shodan open only when you click a lookup, and get only that hash or IP.",
            muted=True))
        layout.addLayout(privacy)

        system = section("System features",
                         "Optional. Each needs a one-time setup with admin rights, and can be removed again.")
        self.dns = FeatureRow("Domain matching",
                              "Shows which website or service each connection belongs to (e.g. api.github.com), "
                              "and checks those names against threat intel. Watches lookups made through "
                              "systemd-resolved; nothing is sent anywhere.")
        self.blocking = FeatureRow("Blocking apps",
                                   "Cut an app off from the internet with a right-click, until it exits or always. "
                                   "Asks for your password each time.")
        self.always = FeatureRow("Always-block service",
                                 "Keeps “always blocked” programs blocked whenever they start, also after a "
                                 "reboot. Only runs while at least one program is always-blocked.")
        for row in (self.dns, self.blocking, self.always):
            system.addWidget(row)
        system.addWidget(divider())
        self.remove = FeatureRow("Remove system setup", "Undoes all of the above and unblocks every app.")
        system.addWidget(self.remove)
        layout.addLayout(system)
        layout.addStretch(1)

        wrapper = QWidget()
        outer = QHBoxLayout(wrapper)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(body)
        outer.addStretch(1)
        self.setWidget(wrapper)

    def refresh(self):
        d, script = self.dash, self.script
        self.popups.switch.blockSignals(True)
        self.popups.switch.setChecked(d.popups_enabled)
        self.popups.switch.blockSignals(False)
        self.popups._show_state(d.popups_enabled)

        dns_on = d.dns.status == "watching"
        self.domain_age.set_note("" if dns_on or not d.ages.enabled else
                                 "Turned on, but it needs domain matching (below) to know which domains to check.")

        own = sorted({p.name for p in d.procs if d.uses_own_dns(p)})
        own_text = ""
        if dns_on and own:
            names = ", ".join(own[:4]) + (" and others" if len(own) > 4 else "")
            own_text = (f"<span style='color:{MUTED_COLOR}'>{html.escape(names)} "
                        f"{'resolves' if len(own) == 1 else 'resolve'} names with {'its' if len(own) == 1 else 'their'} "
                        "own encrypted DNS (DNS-over-HTTPS), so those domains can’t be seen or checked. That’s a "
                        "privacy setting in the app and can stay as it is; its IP addresses are still checked."
                        "</span>")
        if dns_on:
            self.dns.show_state(True, "On: watching lookups", own_text)
        elif d.dns.status == "starting":
            self.dns.show_state(False, "Connecting…")
        elif d.dns.status == "needs-setup":
            self.dns.show_state(False, "Not set up", "To turn it on, run this once in a terminal:",
                                f"sudo {script} --dns")
        else:
            self.dns.show_state(False, "Unavailable", "Needs systemd-resolved, which isn’t running on this computer.",
                                color=WARN_COLOR)

        if blockctl.installed():
            self.blocking.show_state(True, "Ready")
        else:
            self.blocking.show_state(False, "Not set up", "To turn it on, run this once in a terminal:",
                                     f"sudo {script} --blocking")

        count = len(d.always)
        if not blockctl.installed():
            self.always.show_state(False, "Not set up", "Comes with blocking.")
        elif not blockctl.daemon_installed():
            self.always.show_state(False, "Needs an update", "Run the blocking setup again to add it:",
                                   f"sudo {script} --blocking", color=WARN_COLOR)
        elif count and blockctl.daemon_running():
            self.always.show_state(True, f"Running: keeping {count} program{'s' if count != 1 else ''} blocked")
        elif count:
            self.always.show_state(False, "Not running", "It should start on its own; check "
                                   "<code>systemctl status netapp-monitor-blockd</code>.", color=WARN_COLOR)
        else:
            self.always.show_state(False, "Idle: starts when you always-block a program")

        installed = blockctl.installed() or dns_on
        self.remove.setVisible(installed)
        if installed:
            self.remove.show_state(False, "", command=f"sudo {script} --remove")
        self.remove.status.hide()
