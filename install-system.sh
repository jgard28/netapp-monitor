#!/usr/bin/env bash
# One-time, root-only setup for the optional parts of NetApp Monitor that need system
# permissions. Everything else works without it. Pick what you want:
#
#   sudo ./install-system.sh              both features below
#   sudo ./install-system.sh --blocking   only blocking apps from the internet
#   sudo ./install-system.sh --dns        only domain matching
#   sudo ./install-system.sh --remove     uninstall everything and unblock all apps
#
# Blocking: a small helper plus a polkit action. The dashboard asks for your password
#   (cached for a few minutes) whenever you block or unblock. "Always block" uses a small
#   service that only runs while at least one program is always-blocked.
# Domain matching: a polkit rule that lets you (only you, in an active local session)
#   subscribe to systemd-resolved's DNS lookups, so connections can be matched to the
#   domains apps looked up. No password prompt for this one.
set -euo pipefail

case "${1:-}" in
  -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  ""|--blocking|--dns|--remove) ;;
  *) echo "Unknown option: $1 (try --help)" >&2; exit 1 ;;
esac
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo $0 $*" >&2; exit 1; }
src="$(cd "$(dirname "$0")" && pwd)"
helper=/usr/local/libexec/netapp-monitor/netapp-blockctl
policy=/usr/share/polkit-1/actions/io.github.jgard28.netapp-monitor.policy
service=/etc/systemd/system/netapp-monitor-blockd.service
path_unit=/etc/systemd/system/netapp-monitor-blockd.path
rule=/etc/polkit-1/rules.d/50-netapp-monitor.rules
user="${SUDO_USER:-}"

blocking=0 dns=0
case "${1:-}" in
  "") blocking=1 dns=1 ;;
  --blocking) blocking=1 ;;
  --dns) dns=1 ;;
  --remove)
    systemctl disable --now netapp-monitor-blockd.path netapp-monitor-blockd.service 2>/dev/null || true
    [ -x "$helper" ] && "$helper" unblock --all || true
    rm -f "$helper" "$policy" "$rule" "$service" "$path_unit" /etc/netapp-monitor/always-block.json
    rmdir /usr/local/libexec/netapp-monitor /etc/netapp-monitor 2>/dev/null || true
    systemctl daemon-reload
    echo "NetApp Monitor system support removed."
    exit 0 ;;
esac

[ -n "$user" ] && [ "$user" != root ] || { echo "Run this with sudo from your own account (SUDO_USER is not set)." >&2; exit 1; }

if [ "$blocking" = 1 ]; then
  if command -v nft >/dev/null; then
    install -D -o root -g root -m 755 "$src/netapp_monitor/blockctl.py" "$helper"
    install -D -o root -g root -m 644 "$src/data/io.github.jgard28.netapp-monitor.policy" "$policy"
    install -D -o root -g root -m 644 "$src/data/netapp-monitor-blockd.service" "$service"
    install -D -o root -g root -m 644 "$src/data/netapp-monitor-blockd.path" "$path_unit"
    systemctl daemon-reload
    # Older versions enabled the service itself; now the path unit starts it only when needed.
    systemctl disable --quiet netapp-monitor-blockd.service 2>/dev/null || true
    [ -e /etc/netapp-monitor/always-block.json ] || systemctl stop netapp-monitor-blockd.service 2>/dev/null || true
    systemctl enable --now --quiet netapp-monitor-blockd.path
    echo "✔ Blocking installed (right-click an app → Block internet access)."
    echo "  The always-block service stays idle until you always-block a program."
  else
    echo "✖ Skipped blocking: nftables is not installed (pacman -S nftables)." >&2
  fi
fi

if [ "$dns" = 1 ]; then
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
fi
