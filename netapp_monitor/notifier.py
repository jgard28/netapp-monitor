"""Desktop pop-ups for new alerts that close on their own and open the dashboard when clicked."""
from __future__ import annotations

import html
import json
import shutil
import subprocess
import sys
import threading

from PySide6.QtCore import QObject, Signal

APP_NAME = "NetApp Monitor"
ICON = "netapp-monitor"


def reveal_command(pid) -> list[str]:
    launcher = shutil.which("netapp-monitor")
    base = [launcher] if launcher else [sys.executable, "-m", "netapp_monitor"]
    return base + ["--reveal", str(pid or 0)]


class Notifier(QObject):
    """Sends freedesktop notifications through notify-send.

    Pop-ups use normal urgency so every notification daemon expires them after
    `timeout_ms` (daemons keep "critical" ones on screen until dismissed); the daemon's
    close button dismisses them early. Clicking one opens the dashboard on that app:
    via the "Show in dashboard" action on daemons that report actions back (mako, dunst,
    GNOME, KDE), and via the omarchy-exec-argv hint on Omarchy, whose shell runs that
    command when the toast is clicked.
    """

    show_requested = Signal(object)

    def __init__(self):
        super().__init__()
        self.available = shutil.which("notify-send") is not None

    def send(self, title: str, body: str, timeout_ms: int, pid=None):
        threading.Thread(target=self._run, args=(title, body, timeout_ms, pid), daemon=True).start()

    def _run(self, title, body, timeout_ms, pid):
        cmd = ["notify-send", "--wait", "--app-name", APP_NAME, "--icon", ICON,
               "--urgency", "normal", "--expire-time", str(timeout_ms),
               "--hint", "string:omarchy-exec-argv:" + json.dumps(reveal_command(pid)),
               "--action", "default=Show in dashboard", "--action", "show=Show in dashboard",
               title, html.escape(body)]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        except OSError:
            return
        for line in proc.stdout:
            if line.strip() in ("default", "show"):
                self.show_requested.emit(pid)
        proc.wait()
