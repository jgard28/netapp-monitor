#!/usr/bin/env bash
# One-time, root-only setup that lets NetApp Monitor block apps from the internet.
# Installs a small helper and a polkit rule; the dashboard then asks for your password
# (cached for a few minutes) whenever you block or unblock something.
#
#   sudo ./install-blocking.sh            install
#   sudo ./install-blocking.sh --remove   uninstall and unblock everything
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo $0 $*" >&2; exit 1; }
src="$(cd "$(dirname "$0")" && pwd)"
helper=/usr/local/libexec/netapp-monitor/netapp-blockctl
policy=/usr/share/polkit-1/actions/io.github.jgard28.netapp-monitor.policy

if [ "${1:-}" = "--remove" ]; then
  [ -x "$helper" ] && "$helper" unblock --all || true
  rm -f "$helper" "$policy"
  rmdir /usr/local/libexec/netapp-monitor 2>/dev/null || true
  echo "Blocking support removed."
  exit 0
fi

command -v nft >/dev/null || { echo "nftables is required: pacman -S nftables" >&2; exit 1; }
install -D -o root -g root -m 755 "$src/netapp_monitor/blockctl.py" "$helper"
install -D -o root -g root -m 644 "$src/data/io.github.jgard28.netapp-monitor.policy" "$policy"
echo "Blocking support installed. Right-click an app in the dashboard → Block internet access."
