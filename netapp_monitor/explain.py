"""Plain-language explanations for every alert: what it means, when it's harmless, what to check."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Explanation:
    short: str  # one line, for tooltips and pop-ups
    meaning: str
    harmless: str
    check: str


EXPLANATIONS = {
    "intel": Explanation(
        "This address is on a threat-intelligence list of malware servers.",
        "Security researchers saw this IP being used by malware, for example as a command-and-control "
        "(C2) server that infected machines check in with for orders, or to deliver malware.",
        "Lists can be out of date: a server gets cleaned and the IP reused, and shared hosting or CDN "
        "addresses are sometimes listed because one customer was bad. IPsum (medium) is a reputation "
        "list of scanners and brute-forcers, much weaker evidence than ThreatFox or Feodo (high).",
        "Is the app something you installed (see Package)? Look the IP up on AbuseIPDB or VirusTotal "
        "from the right-click menu. If the app is unknown or running from an odd place, block it first "
        "and investigate after."),
    "intel-domain": Explanation(
        "This app connected to a domain listed as malware infrastructure.",
        "The domain name the app looked up is on ThreatFox's list of malware and C2 domains (or your "
        "own blocklist). Subdomains of a listed domain count too.",
        "Rare. Occasionally a legitimate site is compromised and listed until it's cleaned up.",
        "Treat it as serious if the app isn't a browser: block it and check where it came from. In a "
        "browser, think about which page or extension was open at the time."),
    "lookup": Explanation(
        "Something on this computer looked up a known malware domain.",
        "The system resolver saw a lookup for a listed domain, but no current connection explains it. "
        "Malware often resolves its C2 server first; the connection may have been brief or blocked.",
        "A browser prefetching a link, a security tool or mail client checking a URL, or you visiting "
        "a page that embeds it.",
        "The resolver doesn't record which app asked. Look at which apps went online around the same "
        "time, especially new ones, and check the History page."),
    "beacon": Explanation(
        "The app reconnects to the same server on a steady timer.",
        "Malware under remote control usually \"checks in\" with its server every N seconds or minutes "
        "to ask for orders. This app opened a new connection to the same address at least 5 times "
        "with almost identical gaps.",
        "Very common for normal software that polls: update checkers, mail and calendar sync, chat "
        "apps, weather widgets, VPN and sync tools, telemetry.",
        "Is the app installed by your package manager with integrity ✔? Is the destination a vendor "
        "you'd expect (see Host and Network)? A recognized app talking to its own vendor is fine: "
        "trust the destination. An unknown app, a script or a bare IP on a rented server is not."),
    "shell": Explanation(
        "A command shell is connected to the internet.",
        "Shells (bash, sh, nc, socat…) don't normally make network connections themselves. A shell "
        "with an internet socket is the classic sign of a reverse shell: an attacker typing commands "
        "on your machine remotely.",
        "A script that uses bash's /dev/tcp on purpose, or nc/socat you're running yourself.",
        "If you didn't start it, kill it and check the Launched by chain to see what started it."),
    "interpreter": Explanation(
        "A script interpreter (python, node, perl…) is talking to the internet.",
        "Many attacks drop a script rather than a program, so the interpreter is what shows up.",
        "Extremely common: dev tools, package managers, language servers, home-made scripts.",
        "Look at the Command row to see which script is running and decide whether you recognize it."),
    "temp": Explanation(
        "The program runs from a temporary folder.",
        "/tmp, /var/tmp and /dev/shm are writable by everyone and wiped regularly. Installed software "
        "never lives there, but downloaded malware is often saved and run from them.",
        "Rarely: a self-extracting installer or AppImage that unpacks itself and runs once.",
        "If you didn't just run an installer, block or kill it and look at what launched it."),
    "hidden": Explanation(
        "The program runs from a hidden folder.",
        "Folders starting with a dot are hidden from normal file listings, which is why malware likes "
        "them for persistence.",
        "Lots of tools install into hidden folders (editors, language toolchains, launchers). The "
        "common ones are already ignored.",
        "Check the Path and Package rows: do you know what put a program there?"),
    "kthread": Explanation(
        "A normal program is pretending to be a kernel thread.",
        "Kernel threads show up as [kworker/0:1] and the like, with no program file. A process with "
        "a bracketed name but a real program file is disguising itself, a known malware trick.",
        "Essentially never. That's why trusting the app doesn't mute this alert.",
        "Treat it as an incident: block it, note the Path and SHA-256, and investigate."),
    "deleted": Explanation(
        "The program file was deleted or replaced while it was running.",
        "Malware sometimes deletes itself after starting so there's nothing left on disk to scan.",
        "Most often a package update replaced the file; the old version keeps running until you "
        "restart the app.",
        "Did you update recently? If so, restart the app and the alert goes away."),
    "tampered": Explanation(
        "The program file doesn't match what its package installed.",
        "Your package manager recorded a checksum of every file when it installed them. This one "
        "has changed since, which is how a trojanized binary looks.",
        "Hand-edited or locally patched files, or a corrupted package. Reinstalling fixes those.",
        "Reinstall the package (e.g. sudo pacman -S <package>) and see if the alert clears. If it "
        "comes back by itself, something is rewriting the file."),
    "port": Explanation(
        "The connection uses a port associated with malware, proxies or Tor.",
        "Some ports are defaults for attack frameworks (Metasploit 4444, Cobalt Strike 50050), "
        "mining pools or Tor, and malware often doesn't bother changing them.",
        "Any service can run on any port, and some (Tor, SOCKS proxies) are used on purpose.",
        "Do you use Tor, a proxy or a miner on purpose? If not, look at the app."),
    "listen": Explanation(
        "The app is listening on a port associated with backdoors.",
        "A program waiting for incoming connections on a well-known backdoor port could be a bind "
        "shell: a door left open for an attacker to connect in.",
        "A test server or tool you started yourself.",
        "If you didn't start it, kill it and check what launched it."),
    "dga": Explanation(
        "The domain name looks randomly generated.",
        "Some malware generates hundreds of random-looking domains a day and tries them until it "
        "finds its server, which makes it hard to block.",
        "This is a guess from the shape of the name. Some legitimate names look random too.",
        "Look the domain up. If nobody recognizes it and the app is unusual, investigate."),
    "dns-bypass": Explanation(
        "The app does its own DNS, bypassing the system resolver.",
        "Malware sometimes talks to DNS servers directly to avoid local filtering or to tunnel data "
        "out inside DNS queries.",
        "Browsers and some apps use their own secure DNS on purpose (DNS-over-TLS on 853).",
        "Is it a browser, VPN or DNS tool? Then it's expected. Otherwise look closer."),
    "lan-scan": Explanation(
        "The app is probing many devices or ports on your local network.",
        "Attackers who get onto one machine scan the network to find the next one: routers, NAS "
        "boxes, servers. Worms do the same automatically. This app opened connections to many "
        "local addresses, or many ports on one device, in a couple of minutes.",
        "Network tools you run on purpose (nmap, a network scanner app), device discovery in some "
        "media or smart-home apps, or a backup tool walking several machines.",
        "Did you start a scan? If not, look at the app's Path, Package and Launched by rows, and "
        "block it while you investigate."),
    "upload": Explanation(
        "The app uploaded a lot of data recently.",
        "Stealing files means sending them out, so a large unexplained upload is a classic sign of "
        "data theft.",
        "Backups, cloud sync, video calls, git pushes and uploading files yourself.",
        "Was the app supposed to send a lot? Check where it went (Host, Network)."),
}


def explain(topic: str) -> Explanation | None:
    return EXPLANATIONS.get(topic)
