import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor, QImage, QPainter  # noqa: E402
from PySide6.QtWidgets import QApplication, QWidget  # noqa: E402

from netapp_monitor.collector import HIGH, LOW, MEDIUM  # noqa: E402
from netapp_monitor.mascot import (ALARMED, CLEAR, DOZE_AFTER, DOZING, LEARNING, MASCOTS, REACTIONS,  # noqa: E402
                                   WATCHFUL, WORRIED, MascotWidget, Pose, mood_for, reaction_for)

app = QApplication.instance() or QApplication([])


class MoodTest(unittest.TestCase):
    def test_mood_follows_worst_severity(self):
        self.assertEqual(mood_for(0), CLEAR)
        self.assertEqual(mood_for(0, learning=True), LEARNING)
        self.assertEqual(mood_for(LOW, learning=True), WATCHFUL)  # an alert beats learning
        self.assertEqual(mood_for(MEDIUM), WORRIED)
        self.assertEqual(mood_for(HIGH), ALARMED)

    def test_dozes_only_after_a_long_quiet_spell(self):
        self.assertEqual(mood_for(0, quiet_for=DOZE_AFTER - 1), CLEAR)
        self.assertEqual(mood_for(0, quiet_for=DOZE_AFTER), DOZING)
        self.assertEqual(mood_for(0, learning=True, quiet_for=DOZE_AFTER), LEARNING)  # never naps while learning
        self.assertEqual(mood_for(LOW, quiet_for=DOZE_AFTER), WATCHFUL)

    def test_reactions_only_on_change(self):
        self.assertIsNone(reaction_for(None, HIGH))  # the first reading isn't news
        self.assertIsNone(reaction_for(LOW, LOW))
        self.assertEqual(reaction_for(LOW, HIGH), "startle")
        self.assertEqual(reaction_for(HIGH, 0), "cheer")
        self.assertIsNone(reaction_for(HIGH, LOW))  # better, but not clear yet


class DrawTest(unittest.TestCase):
    def test_every_mascot_draws_every_pose(self):
        for mascot in MASCOTS.values():
            for severity in range(4):
                for reaction in (None, *REACTIONS):
                    img = QImage(100, 100, QImage.Format_ARGB32)
                    img.fill(0)
                    p = QPainter(img)
                    mascot.draw(p, Pose(mood_for(severity), severity, 1.7, 0.0, 0.5, reaction, 0.5))
                    p.end()
                    self.assertGreater(QColor(img.pixel(50, 40)).alpha(), 0, (mascot.key, severity, reaction))

    def test_dozing_draws_with_and_without_motion(self):
        for mascot in MASCOTS.values():
            for t in (0.0, 2.3):
                img = QImage(100, 100, QImage.Format_ARGB32)
                img.fill(0)
                p = QPainter(img)
                mascot.draw(p, Pose(DOZING, 0, t))
                p.end()

    def test_every_mascot_has_something_to_say(self):
        for mascot in MASCOTS.values():
            for situation in (CLEAR, LEARNING, WATCHFUL, WORRIED, ALARMED, DOZING, "cheer", "poke", "wake"):
                self.assertTrue(mascot.quip(situation), (mascot.key, situation))

    def test_tray_icon_shows_the_alert_color(self):
        for mascot in MASCOTS.values():
            for severity in range(4):
                self.assertFalse(mascot.icon(severity).isNull())


class WidgetTest(unittest.TestCase):
    def test_off_means_hidden_and_still(self):
        w = MascotWidget()
        w.set_mascot("")
        self.assertTrue(w.isHidden())
        self.assertFalse(w.timer.isActive())

    def test_animates_only_while_its_window_is_shown(self):
        window = QWidget()
        w = MascotWidget(window)
        w.set_mascot("octopus")
        self.assertFalse(w.timer.isActive())  # window not on screen yet
        window.show()
        self.assertTrue(w.timer.isActive())
        window.hide()  # e.g. closed to the tray
        self.assertFalse(w.timer.isActive())

    def test_without_idle_animations_only_reactions_move(self):
        w = MascotWidget()
        w.set_mascot("tux", idle=False)
        w.show()
        self.assertFalse(w.timer.isActive())
        w.set_state(0, False)
        w.set_state(HIGH, False)
        self.assertEqual(w.reaction, "startle")
        self.assertTrue(w.timer.isActive())
        w.hide()

    def test_dozes_off_and_wakes_up(self):
        w = MascotWidget()
        w.set_mascot("octopus")
        w.set_state(0, False, "All clear")
        self.assertEqual(w.mood, CLEAR)
        self.assertTrue(w.toolTip().endswith("All clear"))
        w.calm_since -= DOZE_AFTER
        w.set_state(0, False)
        self.assertEqual(w.mood, DOZING)
        w.poke()  # a click wakes it
        self.assertEqual((w.mood, w.reaction), (CLEAR, "wake"))
        w.calm_since -= DOZE_AFTER
        w.set_state(MEDIUM, False)  # so does an alert
        self.assertEqual((w.mood, w.reaction), (WORRIED, "startle"))
        self.assertIsNone(w.calm_since)

    def test_quiet_mascot_leaves_quips_out_of_the_tooltip(self):
        w = MascotWidget()
        w.set_mascot("tux", chatty=False)
        w.set_state(0, False, "All clear")
        self.assertEqual(w.toolTip(), "All clear")
        w.set_mascot("tux", chatty=True)
        self.assertIn(w.quip, w.toolTip())


if __name__ == "__main__":
    unittest.main()
