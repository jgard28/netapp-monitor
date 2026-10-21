import time
import unittest

from netapp_monitor import intel
from netapp_monitor.collector import HIGH, LOW, Connection, Process
from netapp_monitor.detect import analyze, check_connection, check_process
from netapp_monitor.dns import DnsWatcher, looks_generated, parents, parse_result, registrable


class FakeDns:
    def __init__(self, names, lookups=()):
        self.names, self.lookups = names, list(lookups)

    def name_for(self, ip):
        return self.names.get(ip, "")

    def lookups_since(self, since):
        return [(t, d) for t, d in self.lookups if t >= since]


def conn(raddr="203.0.113.7", rport=443):
    return Connection(1, "tcp", "192.168.1.2", 5000, raddr, rport, "ESTABLISHED", "internet")


class ParseTest(unittest.TestCase):
    def test_monitor_reply(self):
        reply = {"state": "success",
                 "question": [{"class": 1, "type": 1, "name": "www.example.com"}],
                 "answer": [
                     {"rr": {"key": {"class": 1, "type": 5, "name": "www.example.com"}, "name": "cdn.example.net"}},
                     {"rr": {"key": {"class": 1, "type": 1, "name": "cdn.example.net"}, "address": [93, 184, 215, 14]}},
                     {"rr": {"key": {"class": 1, "type": 28, "name": "cdn.example.net"},
                             "address": [0x26, 0x06, 0x28, 0, 0x02, 0x20, 0, 1, 0x2, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46]}}]}
        self.assertEqual(parse_result(reply), [("93.184.215.14", "www.example.com"),
                                               ("2606:2800:220:1:248:1893:25c8:1946", "www.example.com")])

    def test_cname_follow_up_credits_original_name(self):
        # Captured from systemd-resolved: the AAAA re-query for a CNAME target.
        reply = {"state": "success",
                 "question": [{"class": 1, "type": 28, "name": "pages.archlinux.org"}],
                 "collectedQuestions": [{"class": 1, "type": 28, "name": "openpgpkey.archlinux.org"}],
                 "answer": [{"rr": {"key": {"class": 1, "type": 28, "name": "pages.archlinux.org"},
                                    "address": [42, 1, 4, 248, 2, 34, 23, 76, 0, 0, 0, 0, 0, 0, 0, 1]},
                             "raw": "", "ifindex": 4}]}
        self.assertEqual(parse_result(reply), [("2a01:4f8:222:174c::1", "openpgpkey.archlinux.org")])

    def test_ready_message_ignored(self):
        self.assertEqual(parse_result({"ready": True}), [])

    def test_failed_lookup_ignored(self):
        self.assertEqual(parse_result({"state": "rcode-failure", "question": [{"name": "x.com"}]}), [])

    def test_watcher_records(self):
        w = DnsWatcher.__new__(DnsWatcher)  # skip the background thread
        import threading
        from collections import OrderedDict, deque
        w.names, w.recent, w.max_entries, w.lock = OrderedDict(), deque(maxlen=10), 2, threading.Lock()
        w.record([("1.1.1.1", "a.com"), ("2.2.2.2", "b.com"), ("3.3.3.3", "c.com")], now=100)
        self.assertEqual(w.name_for("3.3.3.3"), "c.com")
        self.assertEqual(w.name_for("1.1.1.1"), "")  # evicted, oldest first
        self.assertEqual(len(w.lookups_since(50)), 3)


class DomainTest(unittest.TestCase):
    def test_registrable_and_parents(self):
        self.assertEqual(registrable("a.b.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(list(parents("x.y.evil.com")), ["x.y.evil.com", "y.evil.com", "evil.com"])

    def test_generated(self):
        for d in ("xjwqkzpmrtvb.com", "7f3a9c2e1b8d4f6a.info", "d1a2b3.qxzvbnmlkjhg.org"):
            self.assertTrue(looks_generated(d), d)
        for d in ("googleusercontent.com", "d1a2b3c4e5f6.cloudfront.net", "bismarckchiropractor.com",
                  "strengthscoaching.com", "claudeusercontent.com"):
            self.assertFalse(looks_generated(d), d)

    def test_hostfile(self):
        hits = intel.parse_hostfile("# header\n127.0.0.1\tEvil.example.com\n127.0.0.1\tnot a domain\n")
        self.assertEqual(list(hits), ["evil.example.com"])


class DetectionTest(unittest.TestCase):
    def setUp(self):
        self.intel = intel.Intel()
        self.intel.merge("ThreatFox", {"evil.example.com": intel.Hit("ThreatFox", HIGH, "known malware / C2 domain")},
                         domains=True)

    def test_connection_to_listed_subdomain(self):
        c = conn()
        c.domain = "cdn.evil.example.com"
        alert = check_connection(c, self.intel)[0]
        self.assertEqual((alert.severity, alert.kind), (HIGH, "intel"))
        self.assertIn("cdn.evil.example.com: ThreatFox", alert.message)

    def test_analyze_fills_domain_and_reports_unexplained_lookups(self):
        p = Process(1, "curl", "/usr/bin/curl", connections=[conn()])
        dns = FakeDns({"203.0.113.7": "fine.example.org"},
                      lookups=[(time.time(), "fine.example.org"), (time.time(), "evil.example.com")])
        procs = analyze([p], self.intel, dns=dns)
        self.assertEqual(p.connections[0].domain, "fine.example.org")
        unknown = [x for x in procs if x.name == "DNS lookup (app unknown)"][0]
        self.assertIn("evil.example.com", unknown.alerts[0].message)
        self.assertEqual(procs[0], unknown)  # sorted to the top

    def test_dns_bypass(self):
        p = Process(1, "app", "/usr/bin/app", connections=[conn("8.8.8.8", 53)])
        self.assertIn(LOW, [a.severity for a in check_process(p)])
        resolver = Process(2, "systemd-resolve", "/usr/lib/systemd/systemd-resolved", connections=[conn("9.9.9.9", 853)])
        self.assertEqual(check_process(resolver), [])


if __name__ == "__main__":
    unittest.main()
