import tempfile
import unittest
from pathlib import Path

from netapp_monitor.collector import HIGH, LOW, MEDIUM, Alert, Connection, Process
from netapp_monitor.memory import Baseline, Trust, network_key


def make(exe="/usr/bin/app", raddr="8.8.8.8", alerts=(), conn_alerts=()):
    c = Connection(1, "tcp", "192.168.1.2", 5000, raddr, 443, "ESTABLISHED", "internet", list(conn_alerts))
    return Process(1, "app", exe, connections=[c], alerts=list(alerts))


class TrustTest(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "trust.json"
        self.trust = Trust(self.path)

    def test_trusted_app_mutes_heuristics_but_not_known_c2(self):
        p = make(alerts=[Alert(LOW, "interpreter")],
                 conn_alerts=[Alert(MEDIUM, "port 4444"), Alert(HIGH, "ThreatFox: C2", kind="intel")])
        self.trust.set_app("/usr/bin/app", True)
        self.trust.apply([p])
        self.assertTrue(p.alerts[0].muted)
        self.assertTrue(p.connections[0].alerts[0].muted)
        self.assertFalse(p.connections[0].alerts[1].muted)
        self.assertEqual(p.severity, HIGH)

    def test_disguised_process_never_muted(self):
        p = make(alerts=[Alert(HIGH, "Disguised as a kernel thread", kind="never-mute")])
        self.trust.set_app("/usr/bin/app", True)
        self.trust.apply([p])
        self.assertEqual(p.severity, HIGH)

    def test_trusted_destination(self):
        p = make(conn_alerts=[Alert(MEDIUM, "IPsum: bad reputation", kind="intel")])
        self.trust.set_destination("8.8.8.8", True)
        self.trust.apply([p])
        self.assertEqual(p.severity, 0)

    def test_persists_and_untrusts(self):
        self.trust.set_app("/usr/bin/app", True)
        self.assertIn("/usr/bin/app", Trust(self.path).apps)
        self.trust.set_app("/usr/bin/app", False)
        self.assertEqual(len(Trust(self.path)), 0)


class BaselineTest(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "baseline.json"

    def test_learning_then_new(self):
        b = Baseline(self.path, learning=100, new_for=1000)
        t0 = b.created
        known = make(exe="/usr/bin/known")
        b.observe([known], now=t0 + 10)  # during learning
        self.assertFalse(known.new)

        later = make(exe="/usr/bin/known", raddr="203.0.113.5")
        newcomer = make(exe="/tmp/newcomer")
        b.observe([later, newcomer], now=t0 + 200)
        self.assertFalse(later.new)
        self.assertTrue(later.connections[0].new)  # new destination network for a known app
        self.assertTrue(newcomer.new)

        again = make(exe="/tmp/newcomer")
        b.observe([again], now=t0 + 200 + 1001)  # tag expires
        self.assertFalse(again.new)

    def test_same_network_not_new(self):
        b = Baseline(self.path, learning=0)
        b.observe([make(raddr="8.8.8.8")], now=b.created + 1)
        p = make(raddr="8.8.8.200")
        b.observe([p], now=b.created + 2)
        self.assertTrue(p.connections[0].new)  # still within new_for of the first contact
        self.assertEqual(network_key("8.8.8.200"), network_key("8.8.8.8"))

    def test_persists(self):
        b = Baseline(self.path, learning=0)
        b.observe([make()], now=b.created + 1)
        b.save()
        self.assertIn("/usr/bin/app", Baseline(self.path).apps)


if __name__ == "__main__":
    unittest.main()
