#!/usr/bin/env bash
# Harmless simulations of the things NetApp Monitor flags, so you can watch them in the UI.
# Every "suspicious" connection goes to a well-known benign host (Cloudflare, Google DNS,
# portquiz.net). Everything is cleaned up on exit or Ctrl+C.
#
#   scripts/demo-alerts.sh [seconds]     (default 120)
set -u

DUR="${1:-120}"
LIST="${XDG_CONFIG_HOME:-$HOME/.config}/netapp-monitor/blocklist.txt"
MARK="# netapp-monitor demo"
SHM_BIN="/dev/shm/system-updater"
pids=()

cleanup() {
  trap - EXIT INT TERM
  echo; echo "Cleaning up…"
  kill "${pids[@]}" 2>/dev/null
  wait 2>/dev/null
  rm -f "$SHM_BIN"
  [ -f "$LIST" ] && sed -i "/$MARK/d" "$LIST"
  echo "Done. The alerts will clear from the dashboard within a few seconds."
}
trap cleanup EXIT INT TERM

hold() {  # hold a TCP connection open: hold HOST PORT (runs inside the calling process)
  python3 -c 'import socket,sys,time; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),10); time.sleep(float(sys.argv[3]))' "$1" "$2" "$DUR"
}

echo "Starting simulations for ${DUR}s. Open the dashboard (click the tray icon)."
echo

# HIGH: reverse shell. bash itself keeps a socket to the internet.
bash -c "exec 3<>/dev/tcp/1.1.1.1/80; sleep $DUR; true" &
pids+=($!); echo "  [high]    bash with an internet socket (reverse shell)        -> 1.1.1.1:80"

# HIGH: binary dropped into /dev/shm and run from there.
cp "$(command -v bash)" "$SHM_BIN"
"$SHM_BIN" -c "exec 3<>/dev/tcp/1.0.0.1/80; sleep $DUR; true" &
pids+=($!); echo "  [high]    $SHM_BIN running from a temp dir           -> 1.0.0.1:80"

# HIGH: process masquerading as a kernel thread.
(exec -a "[kworker/u8:3-events]" python3 -c 'import socket,time,sys; s=socket.create_connection(("1.1.1.1",443),10); time.sleep(float(sys.argv[1]))' "$DUR") &
pids+=($!); echo "  [high]    python disguised as [kworker/u8:3-events]          -> 1.1.1.1:443"

# HIGH: destination on a threat-intel blocklist (your personal list, temporarily).
mkdir -p "$(dirname "$LIST")"
echo "8.8.4.4 $MARK" >> "$LIST"
hold 8.8.4.4 53 &
pids+=($!); echo "  [high]    connection to a blocklisted IP                     -> 8.8.4.4:53"

# MEDIUM: Metasploit's default port (portquiz.net answers on every port).
hold portquiz.net 4444 &
pids+=($!); echo "  [medium]  connection to port 4444 (Metasploit default)       -> portquiz.net:4444"

# MEDIUM: listening on a classic backdoor port.
python3 -c 'import socket,time,sys; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",31337)); s.listen(); time.sleep(float(sys.argv[1]))' "$DUR" &
pids+=($!); echo "  [medium]  listener on port 31337 (tick 'Include LAN / loopback / listening')"

# MEDIUM: beaconing. A fresh connection every 10s, like an implant checking in.
python3 -c '
import socket, time, sys
end = time.time() + float(sys.argv[1])
while time.time() < end:
    s = socket.create_connection(("1.0.0.1", 443), 10)
    time.sleep(4)   # stay open long enough for the 3s sampler to see it
    s.close()
    time.sleep(6)
' "$DUR" &
pids+=($!); echo "  [medium]  check-in to 1.0.0.1:443 every 10s (flags after ~45s of beaconing)"

echo
echo "Press Ctrl+C to stop early."
wait
