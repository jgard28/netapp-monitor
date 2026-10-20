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
| high | Remote IP is a known C2 server on [abuse.ch ThreatFox](https://threatfox.abuse.ch/) (currently active C2 for Cobalt Strike, Remcos, VShell, …; the alert names the malware, port, first-seen date and confidence) or [Feodo Tracker](https://feodotracker.abuse.ch/), or is on your own blocklist |
| high | Connection to, or lookup of, a known malware/C2 domain (ThreatFox domains, your blocklist); needs domain matching |
| medium | Remote IP has a bad reputation: listed on 3+ public blocklists ([IPsum](https://github.com/stamparm/ipsum); mostly scanners and brute-forcers) |
| high | Shell or netcat-style tool (`bash`, `sh`, `nc`, `socat`, …) holding an internet connection: possible reverse shell |
| high | Executable running from `/tmp`, `/var/tmp` or `/dev/shm` |
| high | Program file differs from the copy its package installed: its SHA-256 doesn't match the package database (pacman mtree / dpkg md5sums), so it may have been tampered with or trojanized. Never muted by trust |
| high | Process disguising itself as a kernel thread (`[kworker/0:1]` with a real binary behind it) |
| medium | **Beaconing**: an app opens fresh connections to the same host at a steady interval (low jitter), the classic C2 check-in pattern |
| medium | Remote or listening port associated with backdoors, Metasploit, Cobalt Strike, IRC botnets, Tor or mining pools |
| medium | Executable deleted or replaced on disk while running (also normal right after a package update, until the app restarts) |
| low | Script interpreter (`python`, `perl`, `node`, …) talking to the internet |
| low | Executable running from an unusual hidden directory |
| low | Random-looking domain (possible domain-generation malware) |
| low | App does its own DNS straight to the internet, bypassing the system resolver |

Click an app to open its **detail panel**. It shows:

- **A verdict on where the program came from:** "Installed by your package manager (firefox 158.0-1)", or a warning when no package owns the file.
- **How it was launched:** the parent chain, e.g. `bash ← systemd`.
- **Basics:** start time, user and full command line.
- **Integrity:** whether the program file, and every other file in its package, still matches what the package installed (`pacman -Qkk` / `dpkg --verify`). On Linux this is stronger evidence than VirusTotal, which usually hasn't seen distro-built binaries.
- **Its SHA-256** with a VirusTotal button (most useful for programs that didn't come from a package).
- **What the baseline knows:** online since when, and how many networks it has contacted.
- **Its alerts,** plus Block / Trust / Kill buttons.

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

## Trust and "New"

- **Trust:** right-click an app and choose **Trust this app**, or right-click a connection and choose **Trust this destination**, to mute alerts you know are fine. Muted alerts stay in the list, greyed out and marked "(muted)", but they don't color the tray, pop up or push the app to the top. The **Trusted** page lists everything you trust, with a **Remove** button. Two things are never muted: a connection to a known C2 server from threat intel, and a process disguised as a kernel thread. A trusted app doing either is what a hijacked app looks like.
- **New:** NetApp Monitor learns which apps reach the internet and which networks they talk to (grouped by /24 for IPv4, /48 for IPv6, so CDNs don't look new every minute). An app going online for the first time, or a known app reaching a network it has never contacted, is shown in blue for 24 hours. Tick **New only** to see just those. The first 30 minutes are a learning period (shown in the status bar), so the first run doesn't flag your whole system.

State lives in `~/.local/state/netapp-monitor/` (`trust.json`, `baseline.json`). Delete `baseline.json` to start learning again.

## System setup (optional, one time)

Two features need system permissions, and both are enabled by one command:

```sh
sudo ./install-system.sh     # or ~/.local/share/netapp-monitor/install-system.sh after ./install.sh
```

### Blocking apps

Right-click an app on the **Connections** page and choose **Block internet access**. Every running process of that app is moved into its own cgroup (`/sys/fs/cgroup/netapp-blocked`). An nftables rule (`table inet netapp_monitor`) rejects all of their outgoing traffic except loopback, and their open connections are closed. Anything the app launches afterwards is blocked too. The **Blocked** page shows each blocked app with an **Unblock** button.

Blocks are temporary: they last until you unblock the app, it exits, or you reboot. You'll be asked for your password through polkit (cached for a few minutes). Only your own processes can be blocked.

### Domain matching

A polkit rule lets your user (only you, in an active local session, with no password) subscribe to the DNS lookups systemd-resolved answers. NetApp Monitor then:

- **Shows real domains** in the Host column (the name the app actually looked up, e.g. `api.github.com`) instead of reverse-DNS names like `lb-140-82-112-6-iad.github.com`.
- **Matches domains against threat intel:** ThreatFox's ~30k malware/C2 domains, plus domains in your own `blocklist.txt`. Subdomains of a listed domain match too. A connection to a listed domain is a **high** alert.
- **Flags lookups no connection explains.** resolved doesn't say which app asked, so a known-bad domain that was looked up but never connected to shows as **"DNS lookup (app unknown)"** at the top. Malware often resolves its C2 before, or without, connecting.
- **Flags random-looking domains** (low severity), the kind domain-generation malware produces, judged on the registered name only, so CDN subdomains don't trip it.

Apps that do their own DNS (DNS-over-HTTPS in browsers, hard-coded IPs) bypass the system resolver. Their Host column falls back to reverse DNS. An app sending plain DNS or DNS-over-TLS straight to an outside server is itself flagged (low).

Uninstall both with `sudo ./install-system.sh --remove`.

## See it in action

`scripts/demo-alerts.sh` runs harmless simulations of each red flag for two minutes: a fake reverse shell, a binary run from `/dev/shm`, a fake kernel thread, a blocklisted IP, port 4444, a 31337 listener and a beaconing loop. All of them only talk to benign hosts (Cloudflare, Google DNS, portquiz.net). Open the dashboard while it runs; everything is cleaned up when it exits.

```sh
scripts/demo-alerts.sh        # or: scripts/demo-alerts.sh 300
```

## Your own blocklist

Put IPs or domains in `~/.config/netapp-monitor/blocklist.txt`, one per line. Text after `#` is shown as the reason (`203.0.113.9  # from the phishing mail`). The tray app picks up changes live.

## Notes and limits

- **Run as your normal user.** You'll see full details for your own processes. Sockets owned by root or other users still appear, under "owned by another user". To attribute those, run the CLI with `sudo`. Don't run the GUI as root.
- Threat feeds are cached in `~/.cache/netapp-monitor/`. ThreatFox refreshes every 2 hours, the others every 12. The status bar shows how many IPs each source contributed.
- Beacon detection samples every 3 seconds, so it can miss connections that open and close faster than that. A dedicated eBPF/auditd sensor would catch them; that's a possible future addition.
- A flag isn't a verdict. Browsers, sync clients and update checkers can poll on a timer too. Use the lookup links to investigate.

## Development

```sh
python -m unittest discover -s tests
```

MIT licensed.
