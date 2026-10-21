import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="netapp-monitor",
        description="Tray dashboard of every app's network connections, with C2 / malware red flags.")
    parser.add_argument("--tray", action="store_true", help="start minimized to the tray (for autostart)")
    parser.add_argument("--reveal", type=int, metavar="PID", help=argparse.SUPPRESS)
    parser.add_argument("--cli", action="store_true", help="print a one-off report in the terminal")
    parser.add_argument("--json", action="store_true", help="print the report as JSON (implies --cli)")
    parser.add_argument("--all", action="store_true", help="include LAN, loopback and listening sockets")
    parser.add_argument("--lan", action="store_true", help="show connections to devices on your local network")
    parser.add_argument("--alerts", action="store_true", help="only show flagged apps")
    parser.add_argument("--resolve", action="store_true", help="reverse-DNS remote IPs (CLI)")
    parser.add_argument("--offline", action="store_true", help="don't refresh threat-intel feeds (CLI)")
    parser.add_argument("--report", metavar="FILE", help="save a report to FILE (.html or .json) and exit")
    args = parser.parse_args()

    if args.cli or args.json or args.report:
        from .cli import run
        return run(args)
    from .gui import main as gui_main
    return gui_main(start_hidden=args.tray, reveal_pid=args.reveal)


if __name__ == "__main__":
    sys.exit(main())
