import unittest

from netapp_monitor import intel
from netapp_monitor.collector import HIGH, LOW, MEDIUM, Connection, Process, classify_ip, normalize_ip
from netapp_monitor.detect import BeaconTracker, analyze, check_connection, check_process


def conn(raddr="8.8.8.8", rport=443, lport=50000, scope="internet", status="ESTABLISHED", pid=1):
    return Connection(pid, "tcp", "192.168.1.2", lport, raddr, rport, status, scope)


def proc(name="app", exe="/usr/bin/app", conns=None, **kw):
    return Process(pid=1, name=name, exe=exe, connections=conns if conns is not None else [conn()], **kw)


class ClassifyTest(unittest.TestCase):
    def test_scopes(self):
        self.assertEqual(classify_ip("8.8.8.8"), "internet")
        self.assertEqual(classify_ip("2606:4700::1111"), "internet")
        self.assertEqual(classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip("::1"), "loopback")
        self.assertEqual(classify_ip("192.168.7.1"), "lan")
        self.assertEqual(classify_ip("fe80::1%wlan0"), "lan")
        self.assertEqual(classify_ip("100.101.102.103"), "lan")  # Tailscale
        self.assertEqual(classify_ip("::ffff:1.1.1.1"), "internet")

    def test_normalize(self):
        self.assertEqual(normalize_ip("::ffff:10.0.0.1"), "10.0.0.1")
        self.assertEqual(normalize_ip("fe80::1%eth0"), "fe80::1")


class ProcessChecksTest(unittest.TestCase):
    def severities(self, p):
        return [a.severity for a in check_process(p)]

    def test_clean(self):
        self.assertEqual(self.severities(proc()), [])

    def test_temp_dir(self):
        self.assertIn(HIGH, self.severities(proc(exe="/dev/shm/x")))

    def test_deleted(self):
        self.assertIn(MEDIUM, self.severities(proc(exe_deleted=True)))

    def test_reverse_shell(self):
        self.assertIn(HIGH, self.severities(proc(name="bash", exe="/usr/bin/bash")))
        self.assertEqual(self.severities(proc(name="bash", exe="/usr/bin/bash", conns=[])), [])

    def test_fake_kernel_thread(self):
        self.assertIn(HIGH, self.severities(proc(cmdline="[kworker/0:1]")))

    def test_interpreter(self):
        self.assertEqual(self.severities(proc(name="python3.14", exe="/usr/bin/python3.14")), [LOW])


class ConnectionChecksTest(unittest.TestCase):
    def test_blocklist(self):
        alerts = check_connection(conn(raddr="6.6.6.6"), {"6.6.6.6": "feed"})
        self.assertEqual(alerts[0].severity, HIGH)

    def test_ports(self):
        self.assertEqual(check_connection(conn(rport=4444), {})[0].severity, MEDIUM)
        listener = conn(raddr=None, rport=None, lport=31337, scope="listening", status="LISTEN")
        self.assertEqual(check_connection(listener, {})[0].severity, MEDIUM)
        self.assertEqual(check_connection(conn(), {}), [])


class BeaconTest(unittest.TestCase):
    def run_series(self, times):
        tracker = BeaconTracker()
        for i, t in enumerate(times):
            # A fresh connection (new local port) each check-in, closed by the next sample.
            tracker.observe([proc(conns=[conn(lport=40000 + i)])], now=t)
            tracker.observe([proc(conns=[])], now=t + 1)
        return tracker.interval("/usr/bin/app", "8.8.8.8", 443)

    def test_regular_checkins(self):
        self.assertAlmostEqual(self.run_series([0, 60, 120, 181, 240, 300]), 60, delta=1)

    def test_irregular(self):
        self.assertIsNone(self.run_series([0, 5, 90, 100, 400, 410]))

    def test_too_few(self):
        self.assertIsNone(self.run_series([0, 60, 120]))

    def test_long_lived_connection_not_counted(self):
        tracker = BeaconTracker()
        for t in range(0, 600, 3):
            tracker.observe([proc()], now=t)
        self.assertIsNone(tracker.interval("/usr/bin/app", "8.8.8.8", 443))


class AnalyzeTest(unittest.TestCase):
    def test_sorted_worst_first(self):
        clean = proc(name="aaa")
        bad = proc(name="zzz", exe="/tmp/zzz")
        self.assertEqual([p.name for p in analyze([clean, bad])], ["zzz", "aaa"])


class IntelTest(unittest.TestCase):
    def test_parse(self):
        text = "# comment\n1.2.3.4\n5.6.7.8\t3\nnot-an-ip\n\n2001:db8::1 # note\n"
        self.assertEqual(list(intel.parse(text)), ["1.2.3.4", "5.6.7.8", "2001:db8::1"])


if __name__ == "__main__":
    unittest.main()
