import os
import re
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netapp_monitor import blockctl, collector, explain
from netapp_monitor.collector import Connection, Process, Traffic, human_bytes, rate_text
from netapp_monitor.detect import UPLOAD_LIMIT, analyze
from netapp_monitor.geo import GeoDB, Owner, tidy_org
from netapp_monitor.history import History

PKG = Path(collector.__file__).parent


def conn(raddr="8.8.8.8", rport=443, lport=50000):
    return Connection(1, "tcp", "192.168.1.2", lport, raddr, rport, "ESTABLISHED", "internet")


def proc(conns=None, exe="/usr/bin/app"):
    return Process(pid=1, name="app", exe=exe, connections=conns if conns is not None else [conn()])


class ExplainTest(unittest.TestCase):
    def test_every_topic_in_the_code_is_explained(self):
        used = set()
        for path in PKG.glob("*.py"):
            used |= set(re.findall(r'topic="([a-z-]+)"', path.read_text()))
        self.assertGreater(len(used), 10)
        self.assertEqual(used - set(explain.EXPLANATIONS), set())

    def test_alerts_carry_topics(self):
        p = analyze([proc([conn(rport=4444)], exe="/tmp/x")])[0]
        self.assertTrue(all(a.topic for a in p.all_alerts()))


class TrafficTest(unittest.TestCase):
    LINE = ("ESTAB 0 0 192.168.7.96:53934 34.107.243.93:443 cubic wscale:8,10 rto:210 bytes_sent:3372 "
            "bytes_acked:3373 bytes_received:1235 segs_out:12\n"
            "ESTAB 0 0 [::ffff:10.0.0.2]:40000 [2606:4700::1111]:443 cubic bytes_acked:10 bytes_received:20\n"
            "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* cubic\n")

    def test_parses_ss(self):
        with mock.patch("subprocess.run") as run:
            run.return_value.stdout = self.LINE
            counters = collector.tcp_counters()
        self.assertEqual(counters[("192.168.7.96", 53934, "34.107.243.93", 443)], (3373, 1235))
        self.assertEqual(counters[("10.0.0.2", 40000, "2606:4700::1111", 443)], (10, 20))
        self.assertEqual(len(counters), 2)

    def test_rates_and_uploads(self):
        key = ("192.168.1.2", 50000, "8.8.8.8", 443)
        t = Traffic()
        c = conn()
        t.observe([proc([c])], now=100, counters={key: (5_000_000, 1000)})
        self.assertEqual((c.up, c.down), (0.0, 0.0))  # history before monitoring isn't a burst
        c = conn()
        t.observe([proc([c])], now=102, counters={key: (5_002_000, 3000)})
        self.assertEqual((c.up, c.down), (1000.0, 1000.0))
        self.assertEqual(t.uploaded("/usr/bin/app", now=102), 2000)
        # A connection that opens later counts in full.
        new_key = ("192.168.1.2", 50001, "8.8.8.8", 443)
        c2 = conn(lport=50001)
        t.observe([proc([conn(), c2])], now=104, counters={key: (5_002_000, 3000), new_key: (400, 0)})
        self.assertEqual(c2.up, 200.0)
        self.assertEqual(t.uploaded("/usr/bin/app", window=600, now=104), 2400)
        self.assertEqual(t.uploaded("/usr/bin/app", window=600, now=1000), 0)

    def test_big_upload_alert(self):
        t = Traffic()
        key = ("192.168.1.2", 50000, "8.8.8.8", 443)
        t.observe([proc()], now=100, counters={})
        with mock.patch("netapp_monitor.collector.tcp_counters", return_value={key: (UPLOAD_LIMIT + 1, 0)}):
            p = analyze([proc()], traffic=t)[0]
        self.assertEqual([a.topic for a in p.alerts], ["upload"])

    def test_formatting(self):
        self.assertEqual(human_bytes(512), "512 B")
        self.assertEqual(human_bytes(1234), "1.2 KB")
        self.assertEqual(human_bytes(250_000_000), "250 MB")
        self.assertEqual(rate_text(0, 0), "")
        self.assertIn("↓ 2.0 KB/s", rate_text(10, 2000))


class GeoTest(unittest.TestCase):
    ROWS = ["1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n",
            "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n",
            "95.216.0.0\t95.217.255.255\t24940\tDE\tHETZNER-AS\n",
            "2a01:4f8::\t2a01:4f9:ffff:ffff:ffff:ffff:ffff:ffff\t24940\tDE\tHETZNER-AS\n",
            "5.5.5.0\t5.5.5.255\t64500\tNL\tEXAMPLE-AS Example Hosting B.V.\n"]

    def setUp(self):
        self.geo = GeoDB(path="/nonexistent", update=False, background=False)
        self.geo.parse(self.ROWS)

    def test_lookup(self):
        self.assertEqual(self.geo.lookup("1.0.0.1").org, "Cloudflare")
        self.assertIsNone(self.geo.lookup("1.0.2.1"))  # not routed
        self.assertIsNone(self.geo.lookup("9.9.9.9"))
        hetzner = self.geo.lookup("2a01:4f8:c0c::1")
        self.assertEqual((hetzner.country, hetzner.hosting), ("DE", True))
        self.assertTrue(self.geo.lookup("5.5.5.5").hosting)  # "Hosting" in the name
        self.assertFalse(self.geo.lookup("1.0.0.1").hosting)

    def test_labels(self):
        self.assertEqual(Owner(1, "DE", "Hetzner", True).label(), "🇩🇪 DE · Hetzner (rented server)")
        self.assertEqual(Owner(1, "", "Someone", False).label(), "Someone")
        self.assertEqual(tidy_org(1, "GTELECOM-AS-AP Gtelecom Pty Ltd"), "Gtelecom Pty Ltd")
        self.assertEqual(tidy_org(1, "QUAD9-AS-1"), "Quad9")
        self.assertEqual(tidy_org(1, "Wantelco SAS de CV"), "Wantelco SAS de CV")

    def test_analyze_fills_owner(self):
        p = analyze([proc([conn("95.216.1.1")])], geo=self.geo)[0]
        self.assertEqual(p.connections[0].owner.org, "Hetzner")


class HistoryTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.history = History(Path(self.dir.name) / "h.db")

    def tearDown(self):
        self.history.db.close()
        self.dir.cleanup()

    def test_connections_open_update_and_close(self):
        c = conn()
        c.sent = 10
        self.history.record([proc([c])], now=1000)
        c2 = conn()
        c2.sent, c2.domain = 50, "dns.google"
        self.history.record([proc([c2])], now=1010)
        self.history.record([proc([])], now=1020)  # closed
        rows = self.history.destinations(0)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["count"], r["first"], r["last"], r["sent"], r["domain"]), (1, 1000, 1010, 50, "dns.google"))
        self.assertEqual(self.history.destinations(0, "google")[0]["raddr"], "8.8.8.8")
        self.assertEqual(self.history.destinations(0, "nothing-like-this"), [])
        self.assertEqual(self.history.destinations(2000), [])

    def test_alerts_logged_once_per_hour(self):
        p = analyze([proc([conn(rport=4444)])])[0]
        for now in (1000, 1003, 1006):
            self.history.record([p], now=now)
        self.assertEqual(len(self.history.alerts(0)), 1)
        self.history.record([p], now=1000 + 3601)
        self.assertEqual(len(self.history.alerts(0)), 2)
        self.assertEqual(self.history.alerts(0)[0]["topic"], "port")
        self.assertEqual(self.history.app_summary("/usr/bin/app", 0), (1, 2))

    def test_prune(self):
        self.history.record([proc()], now=1000)
        self.history.record([proc([])], now=1001)
        self.history.prune(now=1000 + 31 * 86400)
        self.assertEqual(self.history.destinations(0), [])


class AlwaysBlockTest(unittest.TestCase):
    def test_parse_exec_events(self):
        def event(what, pid, tgid):
            proc_event = struct.pack("=IIQ", what, 0, 0) + struct.pack("=II", pid, tgid)
            cn = struct.pack("=IIIIHH", 1, 1, 0, 0, len(proc_event), 0) + proc_event
            return struct.pack("=IHHII", 16 + len(cn), 3, 0, 0, 0) + cn
        data = event(blockctl.PROC_EVENT_EXEC, 42, 42) + event(0x1, 7, 7) + event(blockctl.PROC_EVENT_EXEC, 43, 40)
        self.assertEqual(blockctl.parse_exec_pids(data), [42, 40])

    def test_enforce_ignores_unlisted_and_other_users(self):
        me = os.getpid()
        self.assertEqual(blockctl.enforce([me], {}), [])
        self.assertEqual(blockctl.enforce([me], {"/not/this": {"uid": os.getuid()}}), [])
        other = os.getuid() + 1
        self.assertEqual(blockctl.enforce([me], {blockctl.exe_of(me): {"uid": other}}), [])

    def test_always_list_reads_missing_as_empty(self):
        with mock.patch.object(blockctl, "ALWAYS", "/nonexistent/always.json"):
            self.assertEqual(blockctl.always_blocked(), {})


if __name__ == "__main__":
    unittest.main()
