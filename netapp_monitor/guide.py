"""The Guide page: a short tour for new users, hosted by the mascot. What the colors, columns and
actions mean, a table of the mascot's moods, a demo that plays them, and a few common questions."""
from __future__ import annotations

import html

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtWidgets import (
    QButtonGroup, QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)
from shiboken6 import isValid

from .collector import HIGH, LOW, MEDIUM, SEVERITY_COLORS
from .mascot import ALARMED, CLEAR, DOZING, LEARNING, MASCOTS, WATCHFUL, WORRIED, MascotWidget, Pose
from .settingspage import MUTED_COLOR, _label, divider, section

STEP_MS = 4500

# (pose, severity, reaction, name, what it means). The same words drive the table and the demo.
MOODS = [
    (CLEAR, 0, None, "Relaxed", "Nothing is flagged. Nothing to do."),
    (LEARNING, 0, None, "Looking around",
     "The first 30 minutes: it's learning which apps normally go online, so nothing is called “new” yet."),
    (WATCHFUL, LOW, None, "One eyebrow up",
     "A <b>low</b> alert (yellow): something a bit unusual, often harmless, like a script talking to the "
     "internet. Have a look when it suits you."),
    (WORRIED, MEDIUM, None, "Worried",
     "A <b>medium</b> alert (orange): worth a look, e.g. an address with a bad reputation or a steady "
     "check-in pattern. Open the app and read <i>What does this mean?</i>"),
    (ALARMED, HIGH, None, "Alarmed",
     "A <b>high</b> alert (red): check now, e.g. a known malware server or a possible reverse shell. "
     "Click the mascot to jump straight to it."),
    (WORRIED, MEDIUM, "startle", "Startled", "An alert just got more serious."),
    (ALARMED, HIGH, "block", "Blocking",
     "You blocked an app (right-click → <i>Block internet access</i>) and it worked: Tux swings his sword, the "
     "octopus snips the app's cable. It never blocks anything on its own."),
    (CLEAR, 0, "cheer", "Cheering", "Everything is clear again."),
    (DOZING, 0, None, "Dozing",
     "Nothing flagged for 10 minutes. It's still watching: the tray icon stays awake."),
    (CLEAR, 0, "wake", "Waking up",
     "Click it any time: it wakes up, or, when something is flagged, jumps to the most serious alert."),
]

# The demo: (mood index in MOODS, what to do with the mascot)
DEMO = [
    (0, lambda w: w.set_state(0, False)),
    (1, lambda w: w.set_state(0, True)),
    (2, lambda w: w.set_state(LOW, False)),
    (3, lambda w: w.set_state(MEDIUM, False)),
    (4, lambda w: w.set_state(HIGH, False)),
    (6, lambda w: w.react("block")),
    (7, lambda w: w.set_state(0, False)),
    (8, lambda w: w.doze_now()),
    (9, lambda w: w.poke()),
]

COLUMNS = [
    ("Application / connection", "The app (bold), and under it each of its connections. Click the arrow to "
                                 "show or hide them."),
    ("Alerts", "Why it's flagged, plus tags like <i>New</i>, <i>Trusted</i> or <i>Blocked</i>. Hover for details."),
    ("Traffic", "How fast it's sending (↑) and receiving (↓) right now."),
    ("PID", "The process number, e.g. for <code>kill</code> or <code>top</code>. “+1” means more processes share "
            "the row."),
    ("User", "The account the app runs as."),
    ("Proto", "TCP (most traffic) or UDP (e.g. DNS, video calls, QUIC)."),
    ("Local", "Your side of the connection: address and port. Hidden at first."),
    ("Remote", "The other side: the address and port it's talking to."),
    ("Host", "The name behind that address, e.g. api.github.com, or the name you gave a device."),
    ("Network", "Who owns that address, with a flag for the country. “Rented server” marks hosting providers, "
                "which is where most malware servers live (and plenty of honest sites)."),
    ("State", "ESTABLISHED is an open connection; LISTEN waits for others to connect in."),
    ("Scope", "internet, lan (your own network), loopback (this computer) or listening. Hidden at first."),
]

QUESTIONS = [
    ("Does a flag mean I have malware?",
     "No. It means “worth a look”. Browsers, sync clients and updaters can look odd too. Each alert has a "
     "<i>What does this mean?</i> link saying when it's usually harmless and what to check."),
    ("Does it block anything by itself?",
     "Never. It only watches. You can block an app yourself with a right-click (after a one-time setup in "
     "Settings)."),
    ("An alert is fine. How do I stop seeing it?",
     "Right-click the app and choose <i>Trust this app</i>, or right-click a connection and trust that "
     "destination. It stays in the list, greyed out, but no longer colors the tray or pops up."),
    ("Does anything about me leave my computer?",
     "Not unless you turn it on. Settings → <i>Lookups that leave your computer</i> lists exactly what is sent."),
    ("Can I turn the mascot off?",
     "Yes: Settings → Mascot, or right-click the tray icon → Mascot → None. Everything it shows is also in the "
     "list and the tray color."),
]


def dot(color: str) -> str:
    return f"<span style='color:{color}'>●</span>"


class GuidePage(QScrollArea):
    def __init__(self, dash, new_color: str, blocked_color: str):
        super().__init__()
        self.dash = dash
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.step = -1
        self.timer = QTimer(self, interval=STEP_MS, timeout=self.next_step)

        body = QWidget()
        body.setMaximumWidth(780)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(4, 0, 12, 12)
        layout.addWidget(_label("New here? This page explains what NetApp Monitor shows you and what you can do "
                                "about it. It takes about two minutes.", muted=True))

        # --- the mascot: a live one with a demo, then a table of its moods
        mascot = section("Meet the mascot",
                         "It reacts to the most serious alert it can see. Press <b>Play demo</b> to watch every "
                         "mood, or read the table below.")
        self.mascot_buttons = QButtonGroup(self)
        pick = QHBoxLayout()
        pick.addWidget(_label("Show:", muted=True))
        for key, m in MASCOTS.items():
            b = QPushButton(m.icon(0), m.title, checkable=True)
            b.setFlat(True)
            b.setProperty("key", key)
            self.mascot_buttons.addButton(b)
            pick.addWidget(b)
        self.mascot_buttons.buttonClicked.connect(lambda b: self.show_mascot(b.property("key")))
        pick.addStretch(1)
        mascot.addLayout(pick)

        stage = QHBoxLayout()
        self.actor = MascotWidget(size=QSize(150, 128))
        self.actor.setCursor(Qt.ArrowCursor)
        self.actor.setToolTip("")
        stage.addWidget(self.actor, 0, Qt.AlignTop)
        bubble = QVBoxLayout()
        self.caption = _label()
        self.caption.setMinimumHeight(80)
        self.caption.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.caption.setStyleSheet("padding: 8px 12px; border: 1px solid palette(mid); border-radius: 10px;")
        self.play = QPushButton("▶ Play demo")
        self.play.setToolTip("Plays every mood in turn. Only this picture changes; monitoring carries on as usual.")
        self.play.clicked.connect(self.toggle_demo)
        bubble.addWidget(self.caption)
        row = QHBoxLayout()
        row.addWidget(self.play)
        self.progress = QLabel()
        self.progress.setStyleSheet(f"color: {MUTED_COLOR}")
        row.addWidget(self.progress)
        row.addStretch(1)
        bubble.addLayout(row)
        bubble.addStretch(1)
        stage.addLayout(bubble, 1)
        mascot.addLayout(stage)

        self.table = QGridLayout()
        self.table.setHorizontalSpacing(12)
        self.table.setVerticalSpacing(8)
        self.table.setContentsMargins(0, 10, 0, 6)
        self.pictures = []
        for i, (_mood, _severity, _reaction, name, meaning) in enumerate(MOODS):
            picture = QLabel()
            picture.setFixedSize(56, 56)
            self.pictures.append(picture)
            self.table.addWidget(picture, i, 0, Qt.AlignTop)
            self.table.addWidget(_label(f"<b>{name}</b><br>{meaning}"), i, 1)
        self.table.setColumnStretch(1, 1)
        mascot.addLayout(self.table)
        self.mascot_note = _label(muted=True)
        mascot.addWidget(self.mascot_note)
        layout.addLayout(mascot)

        # --- the list
        reading = section("Reading the list")
        reading.addWidget(_label(
            "Each <b>bold row</b> is an app; the rows under it are its connections. The most serious apps are at "
            "the top. Colors:<br>"
            f"{dot(SEVERITY_COLORS[HIGH])} <b>Red</b>: high alert, check now<br>"
            f"{dot(SEVERITY_COLORS[MEDIUM])} <b>Orange</b>: medium alert, worth a look<br>"
            f"{dot(SEVERITY_COLORS[LOW])} <b>Yellow</b>: low alert, often harmless<br>"
            f"{dot(new_color)} <b>Blue</b>: new: an app online for the first time, or a new destination (24 hours)<br>"
            f"{dot(blocked_color)} <b>Grey</b>: blocked, or muted because you trust it<br>"
            "No color: nothing unusual. The tray icon takes the color of the most serious alert "
            f"({dot(SEVERITY_COLORS[0])} green when all is clear)."))
        reading.addWidget(_label(
            "<b>The three views</b> at the top: <i>Internet</i> (the default; where malware talks to its "
            "servers), <i>Local network</i> (your NAS, printer, media server…) and <i>Everything</i> (also "
            "connections inside this computer). <b>Filters</b> shows only flagged or new apps, or pauses the "
            "live updates. Type in the search box to filter by app, address or name."))
        layout.addLayout(reading)

        columns = section("The columns", "Right-click a column header to show or hide columns.")
        columns.addWidget(_label("<table cellspacing='0' cellpadding='4'>" + "".join(
            f"<tr><td style='white-space:nowrap'><b>{html.escape(name)}</b></td><td>{text}</td></tr>"
            for name, text in COLUMNS) + "</table>"))
        layout.addLayout(columns)

        actions = section("What you can do")
        actions.addWidget(_label(
            "• <b>Click an app</b> (or press Enter) for its details: where the program came from, whether its "
            "files are intact, who it talks to, and each alert with <i>What does this mean?</i> Esc closes it.<br>"
            "• <b>Right-click an app</b> to block it from the internet, trust it (mute its alerts), kill it, or "
            "look up the program on VirusTotal.<br>"
            "• <b>Right-click a connection</b> to trust that destination, give a device on your network a name, "
            "or look the address up online.<br>"
            "• <b>History</b> shows every connection and alert of the last 30 days. <b>Blocked</b> and "
            "<b>Trusted</b> list what you've blocked or trusted, with a button to undo.<br>"
            "• <b>Export…</b> saves a report to share with someone helping you.<br>"
            "• <b>Pop-ups</b> appear for new medium and high alerts; click one to jump to the app. Mute them "
            "from the tray menu."))
        layout.addLayout(actions)

        faq = section("Common questions")
        for i, (question, answer) in enumerate(QUESTIONS):
            if i:
                faq.addWidget(divider())
            faq.addWidget(_label(f"<b>{html.escape(question)}</b><br>{answer}"))
        layout.addLayout(faq)
        layout.addStretch(1)

        wrapper = QWidget()
        outer = QHBoxLayout(wrapper)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(body)
        outer.addStretch(1)
        self.setWidget(wrapper)
        self.show_mascot(dash.mascot_key or next(iter(MASCOTS)))

    def show_mascot(self, key: str):
        """Feature the chosen mascot, or the first one when the mascot is off, so the tour always has a host."""
        self.stop_demo()
        for b in self.mascot_buttons.buttons():
            b.setChecked(b.property("key") == key)
        m = MASCOTS[key]
        self.actor.set_mascot(key, idle=True, chatty=False)
        self.actor.reset()
        self.actor.set_state(0, False)
        for picture, (mood, severity, reaction, _name, _meaning) in zip(self.pictures, MOODS):
            picture.setPixmap(m.picture(Pose(mood, severity, 0.0, 0.0, 0.0, reaction, 0.5), 56))
        self.caption.setText(f"<b>Hi, I'm {html.escape(m.called)}!</b>"
                             f"<br><i>“{html.escape(m.quip(CLEAR))}”</i>")
        if self.dash.mascot_key:
            self.mascot_note.setText("Just for fun: the colors in the list and the tray show the same thing.")
        else:
            self.mascot_note.setText("The mascot is off. To have it next to the tabs and in the tray, pick one in "
                                     "Settings → Mascot, or right-click the tray icon → Mascot.")

    def sync(self):
        """On opening the page: feature the mascot chosen in Settings or the tray menu."""
        self.show_mascot(self.dash.mascot_key or self.actor.mascot.key)

    def hideEvent(self, event):  # noqa: N802 (Qt naming)
        if isValid(self.play):  # also called while the app shuts down, after the buttons are gone
            self.stop_demo()
        super().hideEvent(event)

    def toggle_demo(self):
        if self.timer.isActive():
            self.stop_demo()
        else:
            self.actor.reset()
            self.step = -1
            self.play.setText("■ Stop")
            self.next_step()
            self.timer.start()

    def next_step(self):
        self.step += 1
        if self.step >= len(DEMO):
            self.stop_demo()
            self.progress.setText("That's every mood!")
            return
        index, action = DEMO[self.step]
        action(self.actor)
        _mood, _severity, reaction, name, meaning = MOODS[index]
        quip = self.actor.mascot.quip(reaction or self.actor.mood)
        self.caption.setText(f"<b>{name}</b><br>{meaning}<br><i>“{html.escape(quip)}”</i>")
        self.progress.setText(f"{self.step + 1} / {len(DEMO)}")

    def stop_demo(self):
        self.timer.stop()
        self.play.setText("▶ Play demo")
        self.progress.setText("")
