"""Follow the desktop's color theme (Omarchy today) and switch live when it changes.

Only the window colors follow the theme. Alert colors stay fixed: theme color names don't reliably
mean what they say (Osaka Jade's "yellow" is green), and a low alert must never look clean.
"""
from __future__ import annotations

import os
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10: no theme support, the app keeps the system's colors
    tomllib = None

from PySide6.QtCore import QFileSystemWatcher, QObject, QTimer
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


def omarchy_dir() -> Path:
    state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(state) / "omarchy" / "current"


def load_colors(path: Path | None = None) -> dict[str, str] | None:
    """The current Omarchy theme's colors.toml, or None when there isn't one (not Omarchy, or unreadable)."""
    path = path or omarchy_dir() / "theme" / "colors.toml"
    if tomllib is None:
        return None
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    colors = {k: v for k, v in data.items() if isinstance(v, str) and QColor.isValidColorName(v)}
    if "background" not in colors or "foreground" not in colors:
        return None
    colors["mode"] = data.get("mode", "dark")
    return colors


def palette_for(colors: dict[str, str]) -> QPalette:
    """Map an Omarchy color scheme onto Qt's palette roles."""
    def c(*names):
        for name in names:
            if name in colors:
                return QColor(colors[name])
        return QColor(colors["foreground"])

    bg, fg = c("background"), c("foreground")
    base = c("dark_background", "background")  # lists sit slightly deeper than the window
    raised = c("lighter_background", "background")
    muted = c("muted", "dark_foreground")
    accent = c("accent", "blue")
    pal = QPalette()
    for role, color in ((QPalette.Window, bg), (QPalette.WindowText, fg), (QPalette.Base, base),
                        (QPalette.AlternateBase, bg), (QPalette.Text, fg), (QPalette.Button, raised),
                        (QPalette.ButtonText, fg), (QPalette.BrightText, c("bright_foreground", "foreground")),
                        (QPalette.Highlight, c("selection", "accent")), (QPalette.HighlightedText,
                                                                         c("bright_foreground", "foreground")),
                        (QPalette.ToolTipBase, c("darker_background", "dark_background", "background")),
                        (QPalette.ToolTipText, fg), (QPalette.PlaceholderText, muted), (QPalette.Link, accent),
                        (QPalette.LinkVisited, accent), (QPalette.Light, raised), (QPalette.Midlight, raised),
                        (QPalette.Mid, muted), (QPalette.Dark, c("darker_background", "dark_background")),
                        (QPalette.Shadow, c("darker_background", "dark_background"))):
        pal.setColor(role, color)
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        pal.setColor(QPalette.Disabled, role, muted)
    return pal


class ThemeFollower(QObject):
    """Applies the Omarchy theme to the app and re-applies it whenever `omarchy theme set` runs."""

    def __init__(self, app: QApplication, enabled: bool = True):
        super().__init__(app)
        self.app = app
        self.default_style = app.style().name()
        self.default_palette = app.palette()
        self.name = ""  # theme currently applied, "" when using the system's colors
        self.enabled = enabled
        self.watcher = QFileSystemWatcher(self)
        self.watcher.directoryChanged.connect(self._changed)
        self.watcher.fileChanged.connect(self._changed)
        # theme-set rewrites several files in a row; apply once it settles
        self.timer = QTimer(self, singleShot=True, interval=400, timeout=self.apply)
        self.apply()

    def available(self) -> bool:
        return load_colors() is not None

    def set_enabled(self, enabled: bool):
        self.enabled = enabled
        self.apply()

    def _changed(self, _path):
        self.timer.start()

    def _watch(self):
        current = omarchy_dir()
        paths = [p for p in (current, current / "theme", current / "theme.name", current / "theme" / "colors.toml")
                 if p.exists()]
        missing = [p for p in map(str, paths) if p not in self.watcher.files() + self.watcher.directories()]
        if missing:
            self.watcher.addPaths(missing)  # re-added after theme-set replaces the files

    def apply(self):
        self._watch()
        colors = load_colors() if self.enabled else None
        if colors:
            self.app.setStyle("Fusion")  # the one built-in style that draws everything from the palette
            self.app.setPalette(palette_for(colors))
            try:
                self.name = (omarchy_dir() / "theme.name").read_text().strip() or "Omarchy"
            except OSError:
                self.name = "Omarchy"
        elif self.name:
            self.app.setStyle(self.default_style)
            self.app.setPalette(self.default_palette)
            self.name = ""
