"""Side panel with everything worth knowing about one app, for deciding if it belongs."""
from __future__ import annotations

import html
import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QFormLayout, QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QToolButton, QVBoxLayout, QWidget,
)

from .appinfo import parent_chain, started
from .collector import HIGH, SEVERITY_COLORS, SEVERITY_NAMES

OK_COLOR, WARN_COLOR, NEW_COLOR, MUTED_COLOR = "#3fb950", "#d29922", "#58a6ff", "#8b949e"


def chip(text: str, color: str) -> str:
    return (f'<span style="background-color:{color}; color:#0d1117; font-weight:bold;">'
            f'&nbsp;{html.escape(text)}&nbsp;</span>')


esc_ = html.escape


def breakable(text: str, every: int = 24) -> str:
    """Escape for rich text and let long unbroken runs (hashes, paths) wrap in a narrow panel."""
    out = []
    for word in text.split(" "):
        out.append("\u200b".join(word[i:i + every] for i in range(0, len(word), every)) if len(word) > every else word)
    return html.escape(" ".join(out))


def ago(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h {seconds % 3600 // 60} min ago"
    return f"{seconds // 86400} days ago"


class DetailPanel(QFrame):
    def __init__(self, dashboard):
        super().__init__()
        self.dash = dashboard
        self.proc = None
        self.info: dict | None = None
        dashboard.loader.loaded.connect(self._loaded)
        self.setMinimumWidth(360)
        self.setFrameShape(QFrame.StyledPanel)

        self.title = QLabel()
        self.title.setStyleSheet("font-size: 15pt; font-weight: bold;")
        close = QToolButton(text="✕", autoRaise=True, toolTip="Close")
        close.clicked.connect(self.dash.close_details)
        head = QHBoxLayout()
        head.addWidget(self.title, 1)
        head.addWidget(close)

        self.chips = self._label()
        self.verdict = self._label()

        self.fields = {}
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignTop)
        for name in ("Path", "Command", "User", "PID", "Started", "Launched by", "Package", "Integrity",
                     "SHA-256", "Online since", "Networks", "Right now", "Domains"):
            self.fields[name] = self._label()
            form.addRow(f"<span style='color:{MUTED_COLOR}'>{name}</span>", self.fields[name])

        self.vt = QPushButton("Check hash on VirusTotal")
        self.vt.setToolTip("Opens VirusTotal in your browser. Only the hash is sent; the file is never uploaded.")
        self.vt.clicked.connect(lambda: self.info and self.dash.open_url(
            f"https://www.virustotal.com/gui/file/{self.info['sha256']}"))
        copy = QPushButton("Copy hash")
        copy.clicked.connect(lambda: self.info and QGuiApplication.clipboard().setText(self.info["sha256"] or ""))
        hash_row = QHBoxLayout()
        hash_row.addWidget(self.vt)
        hash_row.addWidget(copy)
        hash_row.addStretch(1)

        self.alerts_title = QLabel("<b>Alerts</b>")
        self.alerts = self._label()

        self.block_btn = QPushButton()
        self.trust_btn = QPushButton()
        self.kill_btn = QPushButton("Kill…")
        self.block_btn.clicked.connect(self._block)
        self.trust_btn.clicked.connect(self._trust)
        self.kill_btn.clicked.connect(lambda: self.proc and self.dash.kill(self.proc))
        actions = QHBoxLayout()
        for b in (self.block_btn, self.trust_btn, self.kill_btn):
            actions.addWidget(b)
        actions.addStretch(1)

        body = QWidget()
        layout = QVBoxLayout(body)
        layout.addLayout(head)
        layout.addWidget(self.chips)
        layout.addWidget(self.verdict)
        layout.addSpacing(6)
        layout.addLayout(form)
        layout.addLayout(hash_row)
        layout.addSpacing(6)
        layout.addWidget(self.alerts_title)
        layout.addWidget(self.alerts)
        layout.addStretch(1)
        layout.addLayout(actions)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(body)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    @staticmethod
    def _label():
        label = QLabel()
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        label.setTextFormat(Qt.RichText)
        return label

    # --- content ----------------------------------------------------------------

    def show_process(self, proc):
        """Show `proc`; called on selection and again on every refresh with fresh data."""
        changed = self.proc is None or (proc.pid, proc.exe) != (self.proc.pid, self.proc.exe)
        self.proc = proc
        if changed:
            self.info = None
            if proc.exe:
                self.dash.loader.request(proc.exe, verify=True)
        self._render()

    def _loaded(self, exe, info):
        if self.proc and self.proc.exe == exe:
            self.info = info
            self._render()

    def _render(self):
        p, d, f = self.proc, self.dash, self.fields
        esc = html.escape
        self.title.setText(esc(p.name))

        chips = []
        if p.severity:
            chips.append(chip(f"{SEVERITY_NAMES[p.severity]} risk", SEVERITY_COLORS[p.severity]))
        if p.new:
            chips.append(chip("new", NEW_COLOR))
        if p.pid in d.blocked_pids:
            chips.append(chip("blocked", MUTED_COLOR))
        if p.exe and p.exe in d.trust.apps:
            chips.append(chip("trusted", MUTED_COLOR))
        if p.exe_deleted:
            chips.append(chip("deleted on disk", WARN_COLOR))
        self.chips.setText(" ".join(chips))
        self.chips.setVisible(bool(chips))

        # The verdict answers the first question: is this a program I installed?
        if p.pid is None and p.name.startswith("DNS lookup"):
            verdict, color = ("The system resolver doesn't record which app made a lookup. Check which apps "
                              "went online around the same time, especially new ones."), WARN_COLOR
        elif not p.exe:
            verdict, color = "Can't inspect this process (it belongs to another user).", MUTED_COLOR
        elif self.info is None:
            verdict, color = "Checking where this program came from…", MUTED_COLOR
        elif self.info["package"]:
            verdict, color = f"✔ Installed by your package manager ({self.info['package']}).", OK_COLOR
        else:
            verdict, color = ("⚠ Not installed by any package. Make sure you know where this program "
                              "came from."), WARN_COLOR
        self.verdict.setText(f"<span style='color:{color}'>{esc(verdict)}</span>")

        f["Path"].setText(breakable(p.exe or "unknown"))
        f["Command"].setText(f"<code>{breakable(p.cmdline[:600]) or '—'}</code>")
        f["User"].setText(esc(p.user or "?"))
        f["PID"].setText(str(p.pid or "—"))
        start = started(p.pid) if p.pid else None
        f["Started"].setText(f"{time.strftime('%b %d %H:%M', time.localtime(start))} ({ago(time.time() - start)})"
                             if start else "—")
        chain = parent_chain(p.pid) if p.pid else []
        f["Launched by"].setText(" ← ".join(f"{esc(n)} <span style='color:{MUTED_COLOR}'>({pid})</span>"
                                            for n, pid in chain) or "—")
        if self.info is None:
            f["Package"].setText("…")
            f["Integrity"].setText("…")
            f["SHA-256"].setText("…")
        else:
            f["Package"].setText(esc(self.info["package"] or "none"))
            f["Integrity"].setText(self._integrity_text())
            sha = self.info["sha256"]
            f["SHA-256"].setText(f"<code>{breakable(sha, 16)}</code>" if sha else esc(f"can't read file: {self.info['error']}"))
        self.vt.setEnabled(bool(self.info and self.info["sha256"]))

        known = d.baseline.apps.get(p.exe or p.name)
        if known is None:
            f["Online since"].setText("not seen online yet")
            f["Networks"].setText("—")
        else:
            first = known["first"]
            f["Online since"].setText("seen during the learning period" if not first else
                                      f"{time.strftime('%b %d %H:%M', time.localtime(first))} ({ago(time.time() - first)})")
            n = len(known["dests"])
            f["Networks"].setText(f"{n} network{'s' if n != 1 else ''} contacted so far")
        inet = len(p.internet)
        new = sum(1 for c in p.internet if c.new)
        f["Right now"].setText(f"{inet} internet connection{'s' if inet != 1 else ''}"
                               + (f", {new} to new networks" if new else ""))
        domains = sorted({c.domain for c in p.internet if c.domain})
        f["Domains"].setText(breakable(", ".join(domains[:8]) + (f" +{len(domains) - 8} more" if len(domains) > 8 else ""))
                             if domains else f"<span style='color:{MUTED_COLOR}'>none seen (app may use its own DNS, "
                                             "e.g. DNS-over-HTTPS)</span>")

        lines = []
        for a in p.all_alerts():
            color = MUTED_COLOR if a.muted else SEVERITY_COLORS[a.severity]
            lines.append(f"<span style='color:{color}'>● {'(muted) ' if a.muted else ''}{esc(a.message)}</span>")
        self.alerts.setText("<br>".join(lines) or f"<span style='color:{MUTED_COLOR}'>None</span>")

        blocked = p.pid in d.blocked_pids
        self.block_btn.setText("Unblock" if blocked else "Block internet…")
        self.block_btn.setEnabled(bool(p.pid))
        trusted = bool(p.exe) and p.exe in d.trust.apps
        self.trust_btn.setText("Stop trusting" if trusted else "Trust")
        self.trust_btn.setEnabled(bool(p.exe))
        self.kill_btn.setEnabled(bool(p.pid))

    def _integrity_text(self) -> str:
        info = self.info
        if not info["package"]:
            return f"<span style='color:{MUTED_COLOR}'>nothing to compare against (no package)</span>"
        lines = []
        if info["exe_matches"] is True:
            lines.append(f"<span style='color:{OK_COLOR}'>✔ Program file matches the package</span>")
        elif info["exe_matches"] is False:
            lines.append(f"<span style='color:{SEVERITY_COLORS[HIGH]}'>✖ Program file differs from the package</span>")
        verify = info.get("verify", "pending")
        if verify == "pending":
            lines.append(f"<span style='color:{MUTED_COLOR}'>Verifying all package files…</span>")
        elif verify is None:
            lines.append(f"<span style='color:{MUTED_COLOR}'>Full package check unavailable</span>")
        elif verify["changed"]:
            shown = "<br>".join(f"&nbsp;&nbsp;{breakable(path)} <span style='color:{MUTED_COLOR}'>({esc_(reason)})</span>"
                                for path, reason in verify["changed"][:5])
            more = f"<br>&nbsp;&nbsp;…and {len(verify['changed']) - 5} more" if len(verify["changed"]) > 5 else ""
            total = f" of {verify['files']}" if verify["files"] else ""
            lines.append(f"<span style='color:{SEVERITY_COLORS[HIGH]}'>✖ {len(verify['changed'])}{total} package files "
                         f"changed since install:</span><br>{shown}{more}")
        else:
            total = f"All {verify['files']} package files match" if verify["files"] else "All package files match"
            note = f" ({verify['unreadable']} need root to check)" if verify["unreadable"] else ""
            lines.append(f"<span style='color:{OK_COLOR}'>✔ {total}{note}</span>")
        return "<br>".join(lines)

    # --- actions ----------------------------------------------------------------

    def _block(self):
        if self.proc.pid in self.dash.blocked_pids:
            self.dash.unblock_app(self.proc)
        else:
            self.dash.block_app(self.proc)

    def _trust(self):
        self.dash.set_trust("app", self.proc.exe, self.proc.exe not in self.dash.trust.apps)
