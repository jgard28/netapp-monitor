#!/usr/bin/env bash
# Installs netapp-monitor for the current user using the system Python and its packages.
set -euo pipefail

src="$(cd "$(dirname "$0")" && pwd)"
share="${XDG_DATA_HOME:-$HOME/.local/share}"
bin="$HOME/.local/bin"
dest="$share/netapp-monitor"

python3 -c 'import psutil, PySide6' 2>/dev/null || {
  echo "Missing dependencies. On Arch: sudo pacman -S python-psutil pyside6" >&2
  echo "Elsewhere: pip install psutil PySide6" >&2
  exit 1
}

mkdir -p "$dest" "$bin" "$share/applications" "$share/icons/hicolor/scalable/apps"
rm -rf "$dest/netapp_monitor"
cp -r "$src/netapp_monitor" "$dest/"
mkdir -p "$dest/data"
cp "$src/install-system.sh" "$dest/"
rm -f "$dest/install-blocking.sh"
cp "$src/data/io.github.jgard28.netapp-monitor.policy" "$dest/data/"
install -m644 "$src/data/netapp-monitor.svg" "$share/icons/hicolor/scalable/apps/netapp-monitor.svg"
install -m644 "$src/data/netapp-monitor.desktop" "$share/applications/netapp-monitor.desktop"

cat > "$bin/netapp-monitor" <<EOF
#!/bin/sh
PYTHONPATH="$dest\${PYTHONPATH:+:\$PYTHONPATH}" exec python3 -m netapp_monitor "\$@"
EOF
chmod +x "$bin/netapp-monitor"

echo "Installed. Run: netapp-monitor   (or netapp-monitor --cli)"
[ -f /etc/polkit-1/rules.d/50-netapp-monitor.rules ] || echo "Optional, for blocking apps and domain matching: sudo $dest/install-system.sh"
echo "Autostart in the tray on Hyprland: add 'exec-once = netapp-monitor --tray' to ~/.config/hypr/autostart.conf"
