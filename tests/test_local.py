import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from netapp_monitor.collector import Connection, Process, local_kind, visible_connections
from netapp_monitor.detect import LanScanTracker, analyze
from netapp_monitor.history import History
from netapp_monitor.memory import DeviceNames


def conn(raddr, rport=443, lport=50000, scope=None, status="ESTABLISHED"):
    if scope is None:
        scope = "lan" if raddr.startswith(("192.168.", "100.", "224.", "10.")) else "internet"
    return Connection(1, "tcp", "192.168.7.96", lport, raddr, rport, status, scope)


def proc(conns, exe="/usr/bin/app"):
    return Process(pid=1, name="app", exe=exe, connections=conns)


class ViewTest(unittest.TestCase):
    def setUp(self):
        self.p = proc([conn("8.8.8.8"), conn("192.168.7.239", 8096), conn("224.0.0.251", 5353),
                       Connection(1, "tcp", "127.0.0.1", 8080, None, None, "LISTEN", "listening")])

    def test_views(self):
        self.assertEqual([c.raddr for c in visible_connections(self.p, "internet")], ["8.8.8.8"])
        # Multicast discovery chatter isn't a device you're connected to.
        self.assertEqual([c.raddr for c in visible_connections(self.p, "local")], ["192.168.7.239"])
        self.assertEqual(len(visible_connections(self.p, "all")), 4)
        self.assertEqual(len(visible_connections(self.p, True)), 4)  # old boolean form
        self.assertEqual([c.raddr for c in self.p.local], ["192.168.7.239"])

    def test_local_kind(self):
        self.assertEqual(local_kind("192.168.7.239"), "🏠 Local network")
        self.assertIn("Tailscale", local_kind("100.101.102.103"))
        self.assertEqual(local_kind("224.0.0.251"), "Broadcast / discovery")
        self.assertEqual(local_kind("127.0.0.1"), "This computer")


class DeviceNamesTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "devices.json"

    def tearDown(self):
        self.dir.cleanup()

    def test_name_follows_mac_when_ip_changes(self):
        names = DeviceNames(self.path)
        names.set_name("192.168.7.239", "Media server", {"192.168.7.239": "aa:bb:cc:dd:ee:ff"})
        reloaded = DeviceNames(self.path)
        self.assertEqual(reloaded.name_for("192.168.7.239", {"192.168.7.239": "aa:bb:cc:dd:ee:ff"}), "Media server")
        self.assertEqual(reloaded.name_for("192.168.7.50", {"192.168.7.50": "aa:bb:cc:dd:ee:ff"}), "Media server")
        # A different device that took over the old IP doesn't inherit the name.
        self.assertEqual(reloaded.name_for("192.168.7.239", {"192.168.7.239": "11:22:33:44:55:66"}), "")

    def test_ip_only_and_removal(self):
        names = DeviceNames(self.path)
        names.set_name("100.64.0.5", "Proxmox", {})
        self.assertEqual(names.name_for("100.64.0.5", {}), "Proxmox")
        names.set_name("100.64.0.5", "  ", {})
        self.assertEqual(DeviceNames(self.path).name_for("100.64.0.5", {}), "")


class LanScanTest(unittest.TestCase):
    def test_streaming_is_quiet(self):
        t = LanScanTracker()
        for i in range(40):  # reconnecting to the media server all evening
            t.observe([proc([conn("192.168.7.239", 8096, lport=40000 + i)])], now=i * 3)
        self.assertIsNone(t.check("/usr/bin/app"))

    def test_host_sweep(self):
        t = LanScanTracker()
        for i in range(15):
            t.observe([proc([conn(f"192.168.7.{i + 2}", 22, lport=40000 + i, status="SYN_SENT")])], now=i)
        alert = t.check("/usr/bin/app")
        self.assertEqual(alert.topic, "lan-scan")
        self.assertIn("15 devices", alert.message)

    def test_port_sweep_and_analyze(self):
        t = LanScanTracker()
        for i in range(25):
            p = proc([conn("192.168.7.1", 1000 + i, lport=40000 + i, status="SYN_SENT")])
            result = analyze([p], lan_scan=t)[0]
        self.assertIn("25 ports on 192.168.7.1", result.alerts[0].message)

    def test_old_events_expire(self):
        t = LanScanTracker(window=60)
        for i in range(15):
            t.observe([proc([conn(f"192.168.7.{i + 2}", 22, lport=40000 + i)])], now=i)
        t.observe([proc([])], now=1000)
        self.assertIsNone(t.check("/usr/bin/app"))


class LocalHistoryTest(unittest.TestCase):
    def test_local_connections_recorded_with_scope(self):
        with tempfile.TemporaryDirectory() as d:
            h = History(Path(d) / "h.db")
            media = conn("192.168.7.239", 8096)
            media.device = "Media server"
            h.record([proc([conn("8.8.8.8"), media, conn("224.0.0.251", 5353)])], now=1000)
            h.record([proc([])], now=1003)
            lan = h.destinations(0, scope="lan")
            self.assertEqual([(r["raddr"], r["domain"], r["owner"]) for r in lan],
                             [("192.168.7.239", "Media server", "Local network")])
            self.assertEqual([r["raddr"] for r in h.destinations(0, scope="internet")], ["8.8.8.8"])
            self.assertEqual(len(h.destinations(0)), 2)
            self.assertEqual(h.destinations(0, "media")[0]["raddr"], "192.168.7.239")
            h.db.close()

    def test_old_database_is_upgraded(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "h.db"
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE connections (id INTEGER PRIMARY KEY, app TEXT, name TEXT, pid INTEGER, "
                       "proto TEXT, raddr TEXT, rport INTEGER, domain TEXT, country TEXT, owner TEXT, first REAL, "
                       "last REAL, sent INTEGER, received INTEGER, severity INTEGER, alerts TEXT)")
            now = time.time()  # older rows would be pruned on open
            db.execute("INSERT INTO connections (app, name, raddr, rport, first, last) "
                       "VALUES ('/usr/bin/app', 'app', '1.1.1.1', 443, ?, ?)", (now, now))
            db.commit()
            db.close()
            h = History(path)
            self.assertEqual(h.destinations(0, scope="internet")[0]["raddr"], "1.1.1.1")
            h.db.close()


if __name__ == "__main__":
    unittest.main()
