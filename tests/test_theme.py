import tempfile
import unittest
from pathlib import Path

from PySide6.QtGui import QPalette

from netapp_monitor.theme import load_colors, palette_for

OSAKA = """mode = "dark"
accent = "#509475"
selection = "#32473B"
muted = "#53685B"
background = "#111c18"
dark_background = "#0c1512"
foreground = "#C1C497"
yellow = "#459451"
"""


class ThemeTest(unittest.TestCase):
    def write(self, text):
        path = Path(tempfile.mkdtemp()) / "colors.toml"
        path.write_text(text)
        return path

    def test_missing_or_broken_theme_means_system_colors(self):
        self.assertIsNone(load_colors(Path("/nonexistent/colors.toml")))
        self.assertIsNone(load_colors(self.write("background = ")))
        self.assertIsNone(load_colors(self.write('accent = "#509475"')))  # no background/foreground

    def test_invalid_color_values_are_ignored(self):
        colors = load_colors(self.write(OSAKA + 'red = "not a color"\n'))
        self.assertNotIn("red", colors)
        self.assertEqual(colors["mode"], "dark")

    def test_palette_uses_theme_colors(self):
        pal = palette_for(load_colors(self.write(OSAKA)))
        self.assertEqual(pal.color(QPalette.Window).name(), "#111c18")
        self.assertEqual(pal.color(QPalette.Base).name(), "#0c1512")
        self.assertEqual(pal.color(QPalette.Text).name(), "#c1c497")
        self.assertEqual(pal.color(QPalette.Highlight).name(), "#32473b")
        self.assertEqual(pal.color(QPalette.Link).name(), "#509475")
        self.assertEqual(pal.color(QPalette.Disabled, QPalette.Text).name(), "#53685b")

    def test_minimal_theme_falls_back(self):
        pal = palette_for(load_colors(self.write('background = "#000000"\nforeground = "#ffffff"\n')))
        self.assertEqual(pal.color(QPalette.Base).name(), "#000000")
        self.assertEqual(pal.color(QPalette.Highlight).name(), "#ffffff")

    def test_every_installed_omarchy_theme_loads(self):
        themes = sorted(Path("/usr/share/omarchy/themes").glob("*/colors.toml"))
        if not themes:
            self.skipTest("Omarchy not installed")
        for path in themes:
            with self.subTest(theme=path.parent.name):
                self.assertIsNotNone(load_colors(path))
                palette_for(load_colors(path))


if __name__ == "__main__":
    unittest.main()
