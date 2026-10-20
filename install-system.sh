#!/usr/bin/env bash
# One-time, root-only setup for the parts of NetApp Monitor that need system permissions:
#
#   * Blocking apps from the internet: a small helper plus a polkit action. The dashboard
#     asks for your password (cached for a few minutes) whenever you block or unblock.
#   * Domain matching: a polkit rule that lets you (only you, in an active local session)
#     subscribe to systemd-resolved's DNS lookups, so connections can be matched to the
#     domains apps looked up. No password prompt for this one.
#
#   sudo ./install-system.sh            install
#   sudo ./install-system.sh --remove   uninstall and unblock everything
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo $0 $*" >&2; exit 1; }
src="$(cd "$(dirname "$0")" && pwd)"
helper=/usr/local/libexec/netapp-monitor/netapp-blockctl
policy=/usr/share/polkit-1/actions/io.github.jgard28.netapp-monitor.policy
rule=/etc/polkit-1/rules.d/50-netapp-monitor.rules
user="${SUDO_USER:-}"

if [ "${1:-}" = "--remove" ]; then
  [ -x "$helper" ] && "$helper" unblock --all || true
  rm -f "$helper" "$policy" "$rule"
  rmdir /usr/local/libexec/netapp-monitor 2>/dev/null || true
  echo "NetApp Monitor system support removed."
  exit 0
fi

[ -n "$user" ] && [ "$user" != root ] || { echo "Run this with sudo from your own account (SUDO_USER is not set)." >&2; exit 1; }

# Blocking
if command -v nft >/dev/null; then
  install -D -o root -g root -m 755 "$src/netapp_monitor/blockctl.py" "$helper"
  install -D -o root -g root -m 644 "$src/data/io.github.jgard28.netapp-monitor.policy" "$policy"
  echo "✔ Blocking support installed (right-click an app → Block internet access)."
else
  echo "✖ Skipped blocking: nftables is not installed (pacman -S nftables)." >&2
fi

# Domain matching
if command -v resolvectl >/dev/null && systemctl is-active --quiet systemd-resolved; then
  install -d -m 750 /etc/polkit-1/rules.d
  cat > "$rule" <<EOF
// Installed by NetApp Monitor (install-system.sh): lets $user watch DNS lookups made through
// systemd-resolved, so the dashboard can show and check the domains apps connect to.
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.resolve1.subscribe-query-results" &&
        subject.user == "$user" && subject.local && subject.active) {
        return polkit.Result.YES;
    }
});
EOF
  chmod 644 "$rule"
  echo "✔ Domain matching enabled for $user (DNS lookups via systemd-resolved)."
else
  echo "✖ Skipped domain matching: systemd-resolved is not running." >&2
fi
