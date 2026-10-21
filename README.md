# NetApp Monitor

A small Linux tray app that shows **every application's network connections**, grouped by process, and flags the ones that look like malware or command-and-control (C2) traffic.

It's a threat-hunting dashboard, not a firewall. It never blocks anything on its own or nags you with prompts. It watches, scores and tells you what's worth a closer look.

- **Tray icon** that changes color with the worst finding: green (clean), yellow (low), orange (medium), red (high)
- **Dashboard** (click the icon, or run `netapp-monitor` again): processes sorted worst-first, each expandable into its connections, with reverse DNS, live upload/download rate, and who owns each remote IP (country flag and network, e.g. "🇩🇪 DE · Hetzner (rented server)")
- **Three views:** **Internet** (the default, for spotting C2), **Local network** (what's talking to your media server, NAS, Proxmox box or printer, with names you can give each device) and **Everything** (also loopback, listening ports and broadcast traffic)
- **"What does this mean?"** next to every alert: what it means, when it's usually harmless, and what to check
- **History**: a local 30-day timeline of every internet connection and alert, searchable by app, IP, domain or network
- **Pop-up alerts** for new high and medium findings. They close themselves (20s high, 12s medium), can be dismissed by hand, and open the dashboard on that app when clicked. Bursts are grouped into one summary. Mute them from the tray menu.
- **Block an app from the internet** with a right-click, either until it exits or **always** (every time the program starts, also after a reboot). A minimal **Blocked** page lists what's blocked, with one-click Unblock.
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
| medium | **Local network scan**: an app contacts 12+ devices on your network, or 20+ ports on one device, within 2 minutes (how attackers and worms look for the next machine) |
| medium | Executable deleted or replaced on disk while running (also normal right after a package update, until the app restarts) |
| low | Script interpreter (`python`, `perl`, `node`, …) talking to the internet |
| low | Executable running from an unusual hidden directory |
| low | Random-looking domain (possible domain-generation malware) |
| low | App does its own DNS straight to the internet, bypassing the system resolver |
| low | App uploaded 200 MB or more to the internet in the last 10 minutes (possible data theft; also backups, sync, video calls) |

Every alert has a **What does this mean?** link in the detail panel (and a one-line summary in its tooltip and pop-up) explaining what it means, when it's harmless and what to check.

Click an app to open its **detail panel**. It shows:

- **A verdict on where the program came from:** "Installed by your package manager (firefox 158.0-1)", or a warning when no package owns the file.
- **How it was launched:** the parent chain, e.g. `bash ← systemd`.
- **Basics:** start time, user and full command line.
- **Integrity:** whether the program file, and every other file in its package, still matches what the package installed (`pacman -Qkk` / `dpkg --verify`). On Linux this is stronger evidence than VirusTotal, which usually hasn't seen distro-built binaries.
- **Its SHA-256** with a VirusTotal button (most useful for programs that didn't come from a package).
- **What the baseline knows:** online since when, and how many networks it has contacted.
- **Who it's talking to:** the networks behind its connections, with country flags; rented servers (VPS / hosting providers) are marked, since that's where most malware infrastructure lives.
- **Traffic:** current upload/download rate and bytes on open connections.
- **History:** destinations and alerts in the last 7 days, with a link to the History page.
- **Its alerts,** each with an explanation, plus Block / Trust / Kill buttons.

### Local network

Switch to **Local network** at the top of the Connections page to see connections to other devices on your network, e.g. Firefox streaming from `192.168.7.239:8096`. The Network column reads "🏠 Local network" (or "🔒 Tailscale / CGNAT"), and the Host column shows the device's name from your router's DNS when it has one. Right-click a connection and choose **Name this device…** to call it "Media server": names are remembered by MAC address, so they survive a new IP from DHCP (`~/.local/state/netapp-monitor/devices.json`). Multicast and broadcast discovery traffic (mDNS, SSDP) only appears under **Everything**. Local connections are recorded in History too; filter it with **Local network** to answer "what touched my server yesterday?".

From the terminal: `netapp-monitor --cli --lan`.

### Network owner and country

Each remote IP is matched against [iptoasn.com](https://iptoasn.com/)'s public-domain IP-to-network table (about 9 MB, downloaded to `~/.cache/netapp-monitor/` and refreshed weekly). Lookups are local, so the IPs you connect to are never sent anywhere. Rented-server providers (Hetzner, OVH, DigitalOcean, Vultr, Contabo, M247, …, plus networks with "hosting" or "server" in their name) are marked "(rented server)". That's informational, not an alert: plenty of honest sites run there, but so do most C2 servers.

### Traffic

Rates come from the kernel's per-socket TCP counters (`ss -ti`), sampled every refresh. UDP has no per-socket counters, so QUIC/HTTP3 and other UDP traffic isn't counted.

### History

Every internet connection is recorded when it opens (app, destination, domain, network, bytes, alerts) and every alert when it first appears, in `~/.local/state/netapp-monitor/history.db` (SQLite, kept 30 days, never leaves your computer). The **History** page lists destinations grouped by app, or an alert log, for the last hour, day, week or month.

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
netapp-monitor --cli --lan             # connections to devices on your local network
netapp-monitor --cli --all --resolve   # include LAN/loopback/listening, reverse-DNS remote IPs
netapp-monitor --json --alerts         # flagged apps only, as JSON
```

## Trust and "New"

- **Trust:** right-click an app and choose **Trust this app**, or right-click a connection and choose **Trust this destination**, to mute alerts you know are fine. Muted alerts stay in the list, greyed out and marked "(muted)", but they don't color the tray, pop up or push the app to the top. The **Trusted** page lists everything you trust, with a **Remove** button. Two things are never muted: a connection to a known C2 server from threat intel, and a process disguised as a kernel thread. A trusted app doing either is what a hijacked app looks like.
- **New:** NetApp Monitor learns which apps reach the internet and which networks they talk to (grouped by /24 for IPv4, /48 for IPv6, so CDNs don't look new every minute). An app going online for the first time, or a known app reaching a network it has never contacted, is shown in blue for 24 hours. Tick **New only** to see just those. The first 30 minutes are a learning period (shown in the status bar), so the first run doesn't flag your whole system.

State lives in `~/.local/state/netapp-monitor/` (`trust.json`, `baseline.json`, `history.db`). Delete `baseline.json` to start learning again.

## System setup (optional, one time)

Two features need system permissions, and both are enabled by one command:

```sh
sudo ./install-system.sh     # or ~/.local/share/netapp-monitor/install-system.sh after ./install.sh
```

### Blocking apps

Right-click an app on the **Connections** page and choose **Block internet access**. Every running process of that app is moved into its own cgroup (`/sys/fs/cgroup/netapp-blocked`). An nftables rule (`table inet netapp_monitor`) rejects all of their outgoing traffic except loopback, and their open connections are closed. Anything the app launches afterwards is blocked too. The **Blocked** page shows each blocked app with an **Unblock** button.

By default a block lasts until you unblock the app, it exits, or you reboot. Tick **Always block this program** in the confirmation to make it permanent: the program's path is saved in `/etc/netapp-monitor/always-block.json`, and a small root service (`netapp-monitor-blockd`) watches every program start through the kernel's process-event connector and blocks matching programs the moment they start, also after a reboot. Always-blocked programs stay on the Blocked page even when they aren't running. Unblock removes them. (Blocking a shell or interpreter such as `python3` this way would block every script it runs; the dialog warns you.)

You'll be asked for your password through polkit (cached for a few minutes). Only your own processes can be blocked.

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
