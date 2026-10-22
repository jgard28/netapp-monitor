"""An optional mascot that mirrors the monitor's mood: calm while all is clear, worried at a medium
alert, alarmed at a high one, dozing after a long quiet spell, with a short reaction (and a quip)
when things change.

It's decoration only. Every state it shows is also in the list, the status line and the tray color,
so turning it off loses nothing. Mascots are drawn with QPainter in a 100×100 box; to add one,
subclass Mascot, implement draw(), give it QUIPS and register it in MASCOTS.
"""
from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass

from PySide6.QtCore import QPoint, QPointF, QRect, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import QToolTip, QWidget

from .collector import HIGH, LOW, MEDIUM, SEVERITY_COLORS

CLEAR, WATCHFUL, WORRIED, ALARMED, LEARNING, DOZING = "clear", "watchful", "worried", "alarmed", "learning", "dozing"
REACTIONS = {"startle": 0.8, "cheer": 1.4, "poke": 0.6, "wake": 1.0}  # name -> seconds
DOZE_AFTER = 10 * 60  # seconds of nothing flagged before it nods off
SAY_MS = 4000  # how long a speech bubble stays up
FPS = 30
OUTLINE = "#6e7681"  # keeps dark mascots visible on dark themes and light ones on light themes


def mood_for(severity: int, learning: bool = False, quiet_for: float = 0.0) -> str:
    """The mascot's mood for the worst alert currently seen, and how long nothing has been flagged."""
    if severity >= HIGH:
        return ALARMED
    if severity >= MEDIUM:
        return WORRIED
    if severity >= LOW:
        return WATCHFUL
    if learning:
        return LEARNING
    return DOZING if quiet_for >= DOZE_AFTER else CLEAR


def reaction_for(old: int | None, new: int) -> str | None:
    """A one-off reaction when the worst severity changes: startled when it rises, cheering when it clears."""
    if old is None or old == new:
        return None
    if new > old:
        return "startle"
    return "cheer" if new == 0 else None


@dataclass
class Pose:
    """Everything a mascot needs to draw one frame."""
    mood: str = CLEAR
    severity: int = 0
    t: float = 0.0  # seconds; frozen at 0 when idle animations are off
    blink: float = 0.0  # 0 open .. 1 closed
    look: float = 0.0  # -1 left .. 1 right
    reaction: str | None = None
    progress: float = 0.0  # 0..1 through the reaction

    def bump(self) -> float:
        """A 0..1..0 hump over the reaction, for jumps and squishes."""
        return math.sin(math.pi * self.progress) if self.reaction else 0.0


class Mascot:
    key = ""
    title = ""
    credit = ""
    # Its personality: lines per mood and per reaction. Alarmed lines stay useful: say where to look.
    QUIPS: dict[str, tuple[str, ...]] = {}

    def draw(self, p: QPainter, pose: Pose):
        raise NotImplementedError

    def quip(self, situation: str) -> str:
        return random.choice(self.QUIPS.get(situation) or ("",))

    def icon(self, severity: int, size: int = 64) -> QIcon:
        """A still frame for the tray, always awake so the tray never looks like monitoring stopped.
        The alert color must stay readable at 22 px."""
        pix = QPixmap(size, size)
        pix.fill(Qt.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.Antialiasing)
        p.scale(size / 100, size / 100)
        self.draw(p, Pose(mood_for(severity), severity))
        self.badge(p, severity)
        p.end()
        return QIcon(pix)

    def badge(self, p: QPainter, severity: int):
        """A dot in the alert color; mascots whose body already shows it can skip this."""
        p.setPen(QPen(QColor("#0d1117"), 5))
        p.setBrush(QColor(SEVERITY_COLORS[severity]))
        p.drawEllipse(QPointF(78, 78), 19, 19)


def eye(p: QPainter, x: float, y: float, rx: float, ry: float, pose: Pose, lid="#0d1117"):
    if pose.mood == DOZING and pose.reaction != "wake":  # closed: a sleepy curve
        p.setPen(QPen(QColor(lid), 2, Qt.SolidLine, Qt.RoundCap))
        p.setBrush(Qt.NoBrush)
        path = QPainterPath(QPointF(x - rx, y))
        path.quadTo(QPointF(x, y + ry * 0.7), QPointF(x + rx, y))
        p.drawPath(path)
        return
    p.setPen(Qt.NoPen)
    p.setBrush(QColor("#ffffff"))
    ry *= max(0.08, 1 - pose.blink)
    wide = 1.25 if pose.reaction == "startle" or pose.mood == ALARMED else 1.0
    p.drawEllipse(QPointF(x, y), rx * wide, ry * wide)
    if pose.blink < 0.7:
        p.setBrush(QColor("#0d1117"))
        r = rx * (0.4 if wide > 1 else 0.55)
        p.drawEllipse(QPointF(x + pose.look * rx * 0.4, y + ry * 0.1), r, min(r, ry))


def brows(p: QPainter, cx: float, y: float, gap: float, pose: Pose, color="#0d1117"):
    """Worried brows tilt up in the middle, alarmed ones shoot up, a watchful one is raised."""
    p.setPen(QPen(QColor(color), 2.6, Qt.SolidLine, Qt.RoundCap))
    if pose.mood == WORRIED:
        p.drawLine(QPointF(cx - gap - 5, y + 2), QPointF(cx - gap + 4, y - 2))
        p.drawLine(QPointF(cx + gap + 5, y + 2), QPointF(cx + gap - 4, y - 2))
    elif pose.mood == ALARMED:
        p.drawLine(QPointF(cx - gap - 5, y - 4), QPointF(cx - gap + 4, y - 5))
        p.drawLine(QPointF(cx + gap + 5, y - 4), QPointF(cx + gap - 4, y - 5))
    elif pose.mood == WATCHFUL:
        p.drawLine(QPointF(cx + gap - 5, y - 3), QPointF(cx + gap + 5, y - 1))


def snooze(p: QPainter, x: float, y: float, t: float):
    """Z's drifting up and fading; two still ones when idle animations are off."""
    font = QFont()
    font.setBold(True)
    for i in range(3 if t else 2):
        u = ((t * 0.4 + i / 3) % 1.0) if t else 0.3 + i * 0.4
        font.setPixelSize(round(8 + 6 * u))
        p.setFont(font)
        color = QColor(OUTLINE)
        color.setAlphaF(1 - u * 0.8 if t else 1.0)
        p.setPen(color)
        p.drawText(QPointF(x + 10 * u + 3 * math.sin(u * 6), y - 16 * u), "z")


def breathe(p: QPainter, t: float, base_y: float):
    """A slow rise and fall while asleep, anchored at the feet."""
    s = 1 + 0.025 * math.sin(t * 1.4)
    p.translate(50, base_y)
    p.scale(1 / s ** 0.5, s)
    p.translate(-50, -base_y)


def alarm(p: QPainter, x: float, y: float):
    p.setPen(QPen(QColor(SEVERITY_COLORS[HIGH]), 4, Qt.SolidLine, Qt.RoundCap))
    p.drawLine(QPointF(x, y), QPointF(x, y + 9))
    p.drawPoint(QPointF(x, y + 15))


class Octopus(Mascot):
    """A small octopus juggling network cables. Its body takes the alert color."""
    key = "octopus"
    title = "Octopus"
    CABLES = ("#58a6ff", "#e3b341", "#a371f7")  # ethernet blue, yellow, purple
    THROW = 52  # how high the cables fly
    QUIPS = {
        CLEAR: ("All eight arms accounted for. Nothing fishy here.", "Juggling packets, dropping none.",
                "Everything's going swimmingly.", "Calm waters on the wire."),
        LEARNING: ("New reef! Still learning what normal looks like here.",
                   "Taking notes on who talks to whom. Give me a few minutes."),
        WATCHFUL: ("Hmm, something's a little off. Keeping an eye on it.", "Probably nothing… but I'm watching it."),
        WORRIED: ("That one looks fishy. Have a look at the orange alert.", "Ink levels rising. Worth a closer look."),
        ALARMED: ("All arms on deck! Check the red alert now.", "Ink everywhere! Look at the red one first."),
        DOZING: ("zzz… dreaming of quiet networks", "Napping, one tentacle on the wire."),
        "cheer": ("Phew! Back to calm waters.", "All clear. Tentacles untangled."),
        "poke": ("Hey! I'm juggling here.", "Boop. Nothing to report.", "Still eight arms, still all clear."),
        "wake": ("Huh? I'm up, I'm up!", "Wasn't sleeping. Just resting my eyes. All of them."),
    }

    def badge(self, p, severity):
        pass  # the whole octopus is the alert color

    def draw(self, p, pose):
        body = QColor(SEVERITY_COLORS[pose.severity])
        dark = body.darker(135)
        t, bump = pose.t, pose.bump()
        shake = math.sin(t * 40) * 1.5 if pose.mood == ALARMED and t else 0.0
        lift = -10 * bump if pose.reaction in ("startle", "cheer") else 0.0
        if pose.reaction == "cheer" and pose.progress > 0.5:
            lift = -10 * math.sin(math.pi * (pose.progress - 0.5) * 2)
        dozing = pose.mood == DOZING
        p.save()
        p.translate(shake, 4 + lift + (0 if dozing else math.sin(t * 2) * 1.2))
        if dozing:
            breathe(p, t, 88)
        if pose.reaction in ("poke", "wake"):
            squish = 1 if pose.reaction == "poke" else -1  # a poke squashes, waking up stretches
            p.translate(50, 80)
            p.scale(1 + 0.08 * bump * squish, 1 - 0.1 * bump * squish)
            p.translate(-50, -80)

        juggling = pose.mood in (CLEAR, WATCHFUL) and pose.reaction != "startle"
        speed = 0.45 if pose.mood == WATCHFUL else 0.7
        hands = self.hands(pose, juggling, speed)

        # Lower tentacles, wiggling
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(dark, 6.5, Qt.SolidLine, Qt.RoundCap))
        for i, x in enumerate((38, 46, 54, 62)):
            w = math.sin(t * (0.8 if dozing else 3) + i * 1.3) * 3
            out = (x - 50) * 0.5
            path = QPainterPath(QPointF(x, 56))
            path.cubicTo(QPointF(x + out * 0.3, 70), QPointF(x + out + w, 78), QPointF(x + out * 1.6 + w, 88))
            p.drawPath(path)
        # Arms out to the hands
        p.setPen(QPen(body, 6.5, Qt.SolidLine, Qt.RoundCap))
        for side, (hx, hy) in zip((-1, 1), hands):
            path = QPainterPath(QPointF(50 + side * 16, 50))
            path.cubicTo(QPointF(50 + side * 26, 60), QPointF(hx - side * 4, hy + 10), QPointF(hx, hy))
            p.drawPath(path)
        # Head
        p.setPen(QPen(dark, 1.5))
        p.setBrush(body)
        p.drawEllipse(QPointF(50, 38), 22, 21)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(255, 255, 255, 60))
        p.drawEllipse(QPointF(42, 27), 6, 4)  # shine
        eye(p, 42, 40, 5.5, 6.5, pose)
        eye(p, 58, 40, 5.5, 6.5, pose)
        brows(p, 50, 31, 8, pose)
        self.mouth(p, pose)

        if juggling:
            for i, color in enumerate(self.CABLES):
                u = (t * speed + i / 3) % 1.0
                self.plug(p, *self.arc(u, hands), color)
        elif pose.mood in (ALARMED, DOZING):
            for i, color in enumerate(self.CABLES):  # dropped, or put down for a nap
                self.plug(p, 24 + i * 26, 90, 0.2 * (i - 1), color)
            if dozing:
                snooze(p, 70, 26, t)
            else:
                alarm(p, 50, -3)
        else:
            for (hx, hy), color in zip(hands, self.CABLES):  # held tight
                self.plug(p, hx, hy - 4, -1.57, color)
        p.restore()

    @staticmethod
    def hands(pose, juggling, speed):
        t = pose.t
        if pose.mood == ALARMED or pose.reaction == "cheer":
            wave = math.sin(t * 12) * 3
            return (16, 18 + wave), (84, 18 - wave)
        if juggling:
            dip = math.sin(t * speed * 2 * math.pi * 1.5)
            return (18, 60 + 3 * dip), (82, 60 - 3 * dip)
        return (24, 62), (76, 62)

    @staticmethod
    def arc(u, hands):
        """A 3-ball cascade: left to right over the head, then back."""
        (lx, ly), (rx, ry) = hands
        a, (x0, y0), (x1, y1) = (u * 2, (lx, ly), (rx, ry)) if u < 0.5 else ((u - 0.5) * 2, (rx, ry), (lx, ly))
        x = x0 + (x1 - x0) * a
        y = y0 + (y1 - y0) * a - 4 * Octopus.THROW * a * (1 - a)
        angle = math.atan2((y1 - y0) - 4 * Octopus.THROW * (1 - 2 * a), x1 - x0)
        return x, y, angle

    @staticmethod
    def plug(p, x, y, angle, color):
        """An RJ45 plug with a stub of cable trailing behind it."""
        p.save()
        p.translate(x, y)
        p.rotate(math.degrees(angle))
        p.setPen(QPen(QColor(color), 3, Qt.SolidLine, Qt.RoundCap))
        tail = QPainterPath(QPointF(-4, 0))
        tail.cubicTo(QPointF(-9, -4), QPointF(-12, 4), QPointF(-17, 1))
        p.setBrush(Qt.NoBrush)
        p.drawPath(tail)
        p.setPen(QPen(QColor("#57606a"), 1))
        p.setBrush(QColor("#d0d7de"))
        p.drawRoundedRect(QRectF(-4, -3.5, 9, 7), 1.5, 1.5)
        p.setPen(QPen(QColor("#d4a72c"), 1))
        for dy in (-2, 0, 2):
            p.drawLine(QPointF(3, dy), QPointF(5, dy))
        p.restore()

    @staticmethod
    def mouth(p, pose):
        p.setPen(QPen(QColor("#0d1117"), 2.2, Qt.SolidLine, Qt.RoundCap))
        p.setBrush(Qt.NoBrush)
        if pose.mood == ALARMED or pose.reaction == "startle":
            p.setBrush(QColor("#0d1117"))
            p.drawEllipse(QPointF(50, 51), 3, 3.5)
        elif pose.mood == WORRIED:
            path = QPainterPath(QPointF(44, 52))
            path.cubicTo(QPointF(47, 49), QPointF(53, 49), QPointF(56, 52))
            p.drawPath(path)
        elif pose.mood == WATCHFUL:
            p.drawLine(QPointF(46, 51), QPointF(54, 50))
        elif pose.mood == DOZING:
            p.drawEllipse(QPointF(50, 51), 2, 1.6 + 0.6 * math.sin(pose.t * 1.4))  # snoring softly
        else:
            path = QPainterPath(QPointF(44, 49))
            path.cubicTo(QPointF(47, 54), QPointF(53, 54), QPointF(56, 49))
            p.drawPath(path)


class Tux(Mascot):
    """Tux, the Linux penguin (our own drawing of him)."""
    key = "tux"
    title = "Tux"
    credit = "Tux was created by Larry Ewing (lewing@isc.tamu.edu) with The GIMP."
    ORANGE = QColor("#f5a623")
    QUIPS = {
        CLEAR: ("All quiet. Uptime is a lifestyle.", "Nothing flagged. I'll be over here, compiling.",
                "No alerts. Everything is a file, and every file is fine."),
        LEARNING: ("Building a baseline. Please hold.", "Learning what normal looks like. RTFM-ing your traffic."),
        WATCHFUL: ("Something's slightly odd. Logging it.", "Low alert. Not panicking. Yet."),
        WORRIED: ("That doesn't look right. Check the orange alert.", "Medium alert. Time to read the logs."),
        ALARMED: ("This is not a drill: check the red alert now.", "High alert! Look at the red one first."),
        DOZING: ("zzz… idling at 0% CPU", "Sleeping like a cron job. Wake me if anything changes."),
        "cheer": ("All clear again. Closing the ticket.", "Resolved. Back to compiling."),
        "poke": ("Yes? Everything's fine.", "*waddle waddle* Nothing flagged.", "Have you tried turning it off and on? Kidding, all clear."),
        "wake": ("Wha—? Back online.", "Resuming from suspend…"),
    }

    def draw(self, p, pose):
        t, bump = pose.t, pose.bump()
        shake = math.sin(t * 40) * 1.5 if pose.mood == ALARMED and t else 0.0
        hop = -8 * bump if pose.reaction in ("startle", "cheer") else 0.0
        sway = math.sin(t * 1.6) * 2.5 if pose.mood in (CLEAR, LEARNING) else 0.0
        p.save()
        p.translate(shake, hop)
        if pose.mood == DOZING:
            breathe(p, t, 94)
        p.translate(50, 94)
        p.rotate(sway)
        if pose.reaction in ("poke", "wake"):
            squish = 1 if pose.reaction == "poke" else -1  # a poke squashes, waking up stretches
            p.scale(1 + 0.08 * bump * squish, 1 - 0.1 * bump * squish)
        p.translate(-50, -94)

        outline = QPen(QColor(OUTLINE), 1.5)
        p.setPen(outline)
        p.setBrush(self.ORANGE)
        for x in (38, 62):
            p.drawEllipse(QPointF(x, 92), 10, 4.5)
        # Flippers behind the body
        p.setBrush(QColor("#1b1f24"))
        for side, angle in zip((-1, 1), self.flippers(pose)):
            p.save()
            p.translate(50 + side * 19, 46)
            p.rotate(-side * angle)
            p.drawEllipse(QRectF(-5, -2, 10, 28))
            p.restore()
        p.drawEllipse(QPointF(50, 60), 23, 31)  # body
        p.drawEllipse(QPointF(50, 30), 17, 16)  # head
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#f6f8fa"))
        p.drawEllipse(QPointF(50, 66), 16, 23)  # belly
        p.drawEllipse(QPointF(44.5, 29), 6, 7.5)  # face patches
        p.drawEllipse(QPointF(55.5, 29), 6, 7.5)
        eye(p, 45, 29, 3.5, 4.5, pose)
        eye(p, 55, 29, 3.5, 4.5, pose)
        brows(p, 50, 21, 5.5, pose, "#f6f8fa")
        # Beak, open when alarmed
        p.setPen(QPen(QColor("#b9770e"), 1))
        p.setBrush(self.ORANGE)
        p.drawEllipse(QPointF(50, 38), 7, 3.2)
        if pose.mood == ALARMED or pose.reaction == "startle":
            p.drawEllipse(QPointF(50, 42.5), 5.5, 2.8)
        if pose.mood == ALARMED:
            alarm(p, 80, 4)
        elif pose.mood == DOZING:
            snooze(p, 67, 24, t)
        p.restore()

    @staticmethod
    def flippers(pose):
        """Flipper angles (degrees from hanging down): up when alarmed, flapping when cheering,
        a wave now and then while idle."""
        t = pose.t
        if pose.mood == ALARMED:
            return 150 + math.sin(t * 14) * 8, 150 - math.sin(t * 14) * 8
        if pose.reaction == "cheer":
            flap = 60 + 50 * abs(math.sin(pose.progress * math.pi * 3))
            return flap, flap
        if pose.mood == WORRIED:
            return 5, 5  # held in close
        if pose.mood == DOZING:
            return 12, 12
        if pose.reaction == "wake":
            stretch = 130 * math.sin(math.pi * pose.progress)
            return max(20, stretch), max(20, stretch)
        wave = 0.0
        phase = t % 12
        if pose.mood == CLEAR and phase > 10:
            wave = 100 + 25 * math.sin((phase - 10) * math.pi * 3)
        return 20, max(20, wave)


MASCOTS: dict[str, Mascot] = {m.key: m for m in (Octopus(), Tux())}


class MascotWidget(QWidget):
    """Draws the chosen mascot and runs its animation, only while it's on screen. With chatty on,
    its tooltip leads with a line for the current mood, and it speaks up when something changes."""

    clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(QSize(56, 48))
        self.setCursor(Qt.PointingHandCursor)
        self.mascot: Mascot | None = None
        self.idle = True
        self.chatty = True
        self.severity: int | None = None
        self.learning = False
        self.calm_since: float | None = None  # when the last alert went away
        self.mood = CLEAR
        self.quip = ""
        self.summary = ""
        self.reaction: str | None = None
        self.reaction_start = 0.0
        self.start = time.monotonic()
        self.next_blink = self.start + 2
        self.blink_until = 0.0
        self.look = self.look_target = 0.0
        self.next_look = self.start + 5
        self.timer = QTimer(self, interval=1000 // FPS, timeout=self.update)

    def set_mascot(self, key: str | None, idle: bool = True, chatty: bool = True):
        self.mascot = MASCOTS.get(key or "")
        self.idle, self.chatty = idle, chatty
        self.quip = self.mascot.quip(self.mood) if self.mascot else ""
        self._tooltip()
        self.setVisible(self.mascot is not None)
        self._run()
        self.update()

    def set_state(self, severity: int, learning: bool, summary: str = ""):
        """Called on every refresh with the worst severity and the status summary for the tooltip."""
        now = time.monotonic()
        reaction = reaction_for(self.severity, severity)
        self.severity, self.learning, self.summary = severity, learning, summary
        if severity:
            self.calm_since = None
        elif self.calm_since is None:
            self.calm_since = now
        self._set_mood(mood_for(severity, learning, now - self.calm_since if self.calm_since else 0))
        if reaction and self.mascot:
            self.react(reaction)
        self._tooltip()
        self.update()

    def poke(self):
        """Clicked with nothing to show: wakes it up if it's dozing, otherwise a playful squish."""
        if self.mood == DOZING:
            self.calm_since = time.monotonic()  # stays up for another quiet spell
            self._set_mood(CLEAR)
            self.react("wake")
        else:
            self.react("poke")
        self._tooltip()

    def react(self, name: str):
        self.reaction, self.reaction_start = name, time.monotonic()
        self._run()
        if self.mascot:
            self.say(self.quip if name == "startle" else self.mascot.quip(name))

    def say(self, text: str):
        """A speech bubble under the mascot, only while you're looking at the window."""
        if self.chatty and text and self.isVisible() and self.window().isActiveWindow():
            QToolTip.showText(self.mapToGlobal(QPoint(0, self.height())), text, self, QRect(), SAY_MS)

    def _set_mood(self, mood: str):
        if mood == self.mood:
            return
        self.mood = mood
        self.quip = self.mascot.quip(mood) if self.mascot else ""
        self.timer.setInterval(100 if mood == DOZING else 1000 // FPS)  # breathing doesn't need 30 fps

    def _tooltip(self):
        self.setToolTip("\n\n".join(filter(None, (self.quip if self.chatty else "", self.summary))))

    def mousePressEvent(self, event):  # noqa: N802 (Qt naming)
        if event.button() == Qt.LeftButton:
            self.clicked.emit()

    def showEvent(self, event):  # noqa: N802
        self._run()
        super().showEvent(event)

    def hideEvent(self, event):  # noqa: N802
        self.timer.stop()
        super().hideEvent(event)

    def _run(self):
        """Tick only while visible and moving: always for a reaction, otherwise only with idle animations on."""
        moving = self.mascot is not None and self.isVisible() and (self.idle or self.reaction is not None)
        if moving and not self.timer.isActive():
            self.timer.start()
        elif not moving:
            self.timer.stop()

    def pose(self) -> Pose:
        now = time.monotonic()
        severity = self.severity or 0
        pose = Pose(self.mood, severity)
        if self.reaction:
            elapsed = now - self.reaction_start
            if elapsed >= REACTIONS[self.reaction]:
                self.reaction = None
                self._run()
            else:
                pose.reaction, pose.progress = self.reaction, elapsed / REACTIONS[self.reaction]
        if not self.idle:
            pose.t = (now - self.reaction_start) if pose.reaction else 0.0
            return pose
        pose.t = now - self.start
        if now >= self.next_blink:
            self.blink_until = now + 0.15
            self.next_blink = now + random.uniform(2.5, 6)
        pose.blink = 1.0 if now < self.blink_until else 0.0
        if pose.mood == DOZING:
            self.look_target = 0.0
        elif now >= self.next_look:
            if pose.mood == LEARNING:
                choices = (-1, 1)  # scanning around
            elif pose.mood == WATCHFUL:
                choices = (-1, -1, 0)  # side-eye
            else:
                choices = (-1, 0, 0, 1)
            self.look_target = random.choice(choices)
            self.next_look = now + random.uniform(1.5, 3) if pose.mood == LEARNING else now + random.uniform(4, 9)
        self.look += (self.look_target - self.look) * 0.2
        pose.look = self.look
        return pose

    def paintEvent(self, _event):  # noqa: N802
        if not self.mascot:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        side = min(self.width(), self.height())
        p.translate((self.width() - side) / 2, (self.height() - side) / 2)
        p.scale(side / 100, side / 100)
        self.mascot.draw(p, self.pose())
        p.end()
