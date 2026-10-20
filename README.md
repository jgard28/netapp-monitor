# NetApp Monitor

A small Linux tray app that shows **every application's network connections**, grouped by process, and flags the ones that look like malware or command-and-control (C2) traffic.

It's a threat-hunting dashboard, not a firewall. It never blocks or prompts. It watches, scores and tells you what's worth a closer look.

- **Tray icon** that changes color with the worst finding: green (clean), yellow (low), orange (medium), red (high)
- **Dashboard** (click the icon, or run `netapp-monitor` again): processes sorted worst-first, each expandable into its connections, with reverse DNS
- **Pop-up alerts** for new high and medium findings. They close themselves (20s high, 12s medium), can be dismissed by hand, and open the dashboard on that app when clicked. Bursts are grouped into one summary. Mute them from the tray menu.
- **Block an app from the internet** with a right-click. A minimal **Blocked** page lists what's blocked, with one-click Unblock.
- **CLI / JSON** for a one-off check or scripting: `netapp-monitor --cli`

## What it flags

| Severity | Check |
|---|---|
| high | Remote IP is on a threat-intel blocklist ([abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) botnet C2 list, [IPsum](https://github.com/stamparm/ipsum) level 3) |
| high | Shell or netcat-style tool (`bash`, `sh`, `nc`, `socat`, …) holding an internet connection: possible reverse shell |
| high | Executable running from `/tmp`, `/var/tmp` or `/dev/shm` |
| high | Process disguising itself as a kernel thread (`[kworker/0:1]` with a real binary behind it) |
| medium | **Beaconing**: an app opens fresh connections to the same host at a steady interval (low jitter), the classic C2 check-in pattern |
| medium | Remote or listening port associated with backdoors, Metasploit, Cobalt Strike, IRC botnets, Tor or mining pools |
| medium | Executable deleted or replaced on disk while running (also normal right after a package update, until the app restarts) |
| low | Script interpreter (`python`, `perl`, `node`, …) talking to the internet |
| low | Executable running from an unusual hidden directory |

Right-click a connection to look the IP up on AbuseIPDB, VirusTotal or Shodan. Right-click an app to copy its path or command line, look up its SHA-256 on VirusTotal (only the hash leaves your machine; the file is never uploaded), or kill it.

## Install

Needs Python 3.10+, `psutil` and `PySide6`.

```sh
# Arch / Omarchy
sudo pacman -S python-psutil pyside6
git clone https://github.com/jgard28/netapp-monitor && cd netapp-monitor
./install.sh
```

Or run it straight from the checkout: `python -m netapp_monitor`.

Start it in the tray at login (Hyprland):

```
exec-once = netapp-monitor --tray
```

Any desktop with a StatusNotifierItem tray works: Waybar, the Omarchy bar, KDE, GNOME with the AppIndicator extension, and others. With no tray available it runs as a plain window.

## Usage

```
netapp-monitor              # tray + dashboard (re-running it just raises the window)
netapp-monitor --tray       # start minimized to the tray
netapp-monitor --cli        # one-off grouped report in the terminal
netapp-monitor --cli --all --resolve   # include LAN/loopback/listening, reverse-DNS remote IPs
netapp-monitor --json --alerts         # flagged apps only, as JSON
```

## Blocking apps (optional)

Blocking needs a one-time setup with admin rights:

```sh
sudo ./install-blocking.sh     # or ~/.local/share/netapp-monitor/install-blocking.sh after ./install.sh
```

Then right-click an app on the **Connections** page and choose **Block internet access**. Every running process of that app is moved into its own cgroup (`/sys/fs/cgroup/netapp-blocked`). An nftables rule (`table inet netapp_monitor`) rejects all of their outgoing traffic except loopback, and their open connections are closed. Anything the app launches afterwards is blocked too. The **Blocked** page shows each blocked app with an **Unblock** button.

Blocks are temporary: they last until you unblock the app, it exits, or you reboot. You'll be asked for your password through polkit (cached for a few minutes). Only your own processes can be blocked. Uninstall with `sudo ./install-blocking.sh --remove`.

## See it in action

`scripts/demo-alerts.sh` runs harmless simulations of each red flag for two minutes: a fake reverse shell, a binary run from `/dev/shm`, a fake kernel thread, a blocklisted IP, port 4444, a 31337 listener and a beaconing loop. All of them only talk to benign hosts (Cloudflare, Google DNS, portquiz.net). Open the dashboard while it runs; everything is cleaned up when it exits.

```sh
scripts/demo-alerts.sh        # or: scripts/demo-alerts.sh 300
```

## Your own blocklist

Put IPs (one per line, `#` for comments) in `~/.config/netapp-monitor/blocklist.txt`. The tray app picks up changes live.

## Notes and limits

- **Run as your normal user.** You'll see full details for your own processes. Sockets owned by root or other users still appear, under "owned by another user". To attribute those, run the CLI with `sudo`. Don't run the GUI as root.
- Blocklists are cached in `~/.cache/netapp-monitor/` and refreshed every 12 hours.
- Beacon detection samples every 3 seconds, so it can miss connections that open and close faster than that. A dedicated eBPF/auditd sensor would catch them; that's a possible future addition.
- A flag isn't a verdict. Browsers, sync clients and update checkers can poll on a timer too. Use the lookup links to investigate.

## Development

```sh
python -m unittest discover -s tests
```

MIT licensed.
