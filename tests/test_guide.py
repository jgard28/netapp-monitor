import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from netapp_monitor.guide import DEMO, MOODS, GuidePage  # noqa: E402
from netapp_monitor.mascot import MASCOTS  # noqa: E402

app = QApplication.instance() or QApplication([])


class Dash:
    mascot_key = ""


class GuideTest(unittest.TestCase):
    def test_demo_plays_every_step_then_stops(self):
        page = GuidePage(Dash(), "#58a6ff", "#8b949e")
        page.toggle_demo()
        self.assertTrue(page.timer.isActive())
        seen = []
        for _ in DEMO:
            seen.append(page.actor.mood)
            self.assertIn("“", page.caption.text())  # every step has the mascot's own line
            page.next_step()
        self.assertFalse(page.timer.isActive())
        self.assertEqual(seen[:5], [MOODS[i][0] for i, _ in DEMO[:5]])

    def test_hosted_by_the_chosen_mascot_or_the_first_one(self):
        dash = Dash()
        page = GuidePage(dash, "#58a6ff", "#8b949e")
        self.assertEqual(page.actor.mascot.key, next(iter(MASCOTS)))
        self.assertIn("off", page.mascot_note.text())
        dash.mascot_key = "tux"
        page.sync()
        self.assertEqual(page.actor.mascot.key, "tux")

    def test_leaving_the_page_stops_the_demo(self):
        page = GuidePage(Dash(), "#58a6ff", "#8b949e")
        page.show()
        page.toggle_demo()
        page.hide()
        self.assertFalse(page.timer.isActive())


if __name__ == "__main__":
    unittest.main()
