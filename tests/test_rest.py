import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from netapp_monitor import domainage, report
from netapp_monitor.collector import Alert, Connection, Process, merge_shared
from netapp_monitor.detect import analyze, new_domain_alert


def conn(raddr="8.8.8.8", rport=443, lport=50000, pid=1):
    return Connection(pid, "tcp", "192.168.1.2", lport, raddr, rport, "ESTABLISHED", "internet")


def proc(pid, exe="/usr/bin/app", conns=None, name=None, alerts=None):
    return Process(pid=pid, name=name or exe.rsplit("/", 1)[-1], exe=exe, user="me",
                   connections=conns if conns is not None else [conn(pid=pid)], alerts=alerts or [])


class MergeTest(unittest.TestCase):
    def test_same_program_same_sockets_merge_under_parent(self):
        parent = proc(10, alerts=[Alert(3, "a")])
        child = proc(11, alerts=[Alert(3, "a"), Alert(2, "b")])
        rows = merge_shared([child, parent], parents={10: 1, 11: 10})
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].pid, rows[0].pids), (10, [10, 11]))
        self.assertEqual([a.message for a in rows[0].alerts], ["a", "b"])

    def test_different_programs_stay_separate_but_note_sharing(self):
        shell = proc(10, exe="/usr/bin/bash")
        nc = proc(11, exe="/usr/bin/nc")
        rows = merge_shared([shell, nc], parents={11: 10})
        self.assertEqual(len(rows), 2)
        by_name = {p.name: p for p in rows}
        self.assertEqual(by_name["bash"].connections[0].shared, [("nc", 11)])

    def test_different_sockets_stay_separate(self):
        rows = merge_shared([proc(10), proc(11, conns=[conn(lport=50001, pid=11)])], parents={})
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(not c.shared for p in rows for c in p.connections))

    def test_unknown_owner_rows_untouched(self):
        rows = merge_shared([proc(None, exe=""), proc(None, exe="")], parents={})
        self.assertEqual(len(rows), 2)


class ReportTest(unittest.TestCase):
    def setUp(self):
        flagged = proc(10, conns=[conn(rport=4444)])
        self.procs = analyze([flagged, proc(20, exe="/usr/bin/other", conns=[conn("1.1.1.1", pid=20)])])
        facts = {"package": "app 1.0-1", "sha256": "ab" * 32, "exe_matches": True}
        self.data = report.build(self.procs, intel_summary="ThreatFox 1", cache=lambda exe: facts,
                                 now=1_800_000_000)

    def test_build(self):
        d = self.data
        self.assertEqual(d["summary"]["flagged"], 1)
        app = d["apps"][0]
        self.assertEqual((app["name"], app["severity"], app["package"], app["matches_package"]),
                         ("app", "medium", "app 1.0-1", True))
        self.assertTrue(app["connections"][0]["alerts"][0]["explanation"])
        json.loads(report.to_json(d))

    def test_html_escapes_and_contains_sections(self):
        self.procs[0].cmdline = "<script>alert(1)</script>"
        page = report.to_html(report.build(self.procs, cache=lambda exe: None))
        self.assertNotIn("<script>", page)
        for text in ("Flagged apps (1)", "Other apps online (1)", "Alerts in the last 24 hours"):
            self.assertIn(text, page)

    def test_save_picks_format_by_extension(self):
        with tempfile.TemporaryDirectory() as d:
            report.save(self.data, f"{d}/r.json")
            report.save(self.data, f"{d}/r.html")
            self.assertEqual(json.loads(Path(f"{d}/r.json").read_text())["tool"], "NetApp Monitor")
            self.assertTrue(Path(f"{d}/r.html").read_text().startswith("<!doctype html>"))


class DomainAgeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.ages = domainage.DomainAges(cache_path=f"{self.dir.name}/ages.json",
                                         bootstrap_path=f"{self.dir.name}/boot.json", start=False)

    def tearDown(self):
        self.dir.cleanup()

    def test_parsing(self):
        rdap = {"events": [{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                           {"eventAction": "registration", "eventDate": "2007-10-09T18:20:50Z"}]}
        self.assertEqual(time.gmtime(domainage.registration_date(rdap))[:3], (2007, 10, 9))
        self.assertIsNone(domainage.registration_date({}))
        servers = domainage.servers_from_bootstrap(
            {"services": [[["com", "net"], ["http://x/", "https://rdap.verisign.com/com/v1/"]], [["uk"], ["https://n/uk"]]]})
        self.assertEqual(servers["net"], "https://rdap.verisign.com/com/v1/")
        self.assertEqual(servers["uk"], "https://n/uk/")

    def test_queues_registrable_name_once_and_caches(self):
        self.assertIsNone(self.ages.created("cdn.static.example.com", now=1000))
        self.assertIsNone(self.ages.created("www.example.com", now=1001))
        self.assertEqual(self.ages.jobs.qsize(), 1)
        self.assertEqual(self.ages.jobs.get(), "example.com")
        self.ages.record("example.com", 500.0, now=1002)
        self.assertEqual(self.ages.created("api.example.com", now=1003), 500.0)
        self.ages.save()
        again = domainage.DomainAges(cache_path=self.ages.cache_path, start=False)
        self.assertEqual(again.created("example.com", now=1004), 500.0)
        self.assertTrue(again.jobs.empty())

    def test_skips_local_and_disabled(self):
        for name in ("nas.local", "printer.home.arpa", "localhost", "router.lan"):
            self.assertIsNone(self.ages.created(name))
        self.ages.enabled = False
        self.ages.created("example.org")
        self.assertTrue(self.ages.jobs.empty())

    def test_lookup_uses_the_tld_registry(self):
        self.ages.servers = {"com": "https://rdap.verisign.com/com/v1/"}
        with mock.patch.object(self.ages, "_get", return_value={"events": [
                {"eventAction": "registration", "eventDate": "2026-10-15T00:00:00Z"}]}) as get:
            created = self.ages.lookup("example.com")
        get.assert_called_once_with("https://rdap.verisign.com/com/v1/domain/example.com")
        self.assertEqual(time.gmtime(created)[:3], (2026, 10, 15))
        self.assertIsNone(self.ages.lookup("example.io"))  # no RDAP server for this TLD

    def test_alerts(self):
        now = 2_000_000_000
        self.assertEqual(new_domain_alert("a.evil-new.com", now - 2 * 86400, now).severity, 2)
        alert = new_domain_alert("a.evil-new.com", now - 12 * 86400, now)
        self.assertEqual((alert.severity, alert.topic), (1, "new-domain"))
        self.assertIn("evil-new.com was registered 12 days ago", alert.message)
        self.assertIsNone(new_domain_alert("old.com", now - 400 * 86400, now))
        self.assertIsNone(new_domain_alert("unknown.com", None, now))

    def test_analyze_flags_young_domain(self):
        c = conn()
        c.domain = "login.brand-new.com"
        self.ages.record("brand-new.com", time.time() - 3 * 86400)
        p = analyze([proc(1, conns=[c])], ages=self.ages)[0]
        self.assertEqual([a.topic for a in p.connections[0].alerts], ["new-domain"])


if __name__ == "__main__":
    unittest.main()


class OwnDnsTest(unittest.TestCase):
    def test_known_doh_service(self):
        from netapp_monitor.dns import is_doh, own_dns
        doh = conn("162.159.61.4")
        self.assertTrue(is_doh(doh))
        self.assertFalse(is_doh(conn("162.159.61.4", rport=80)))
        named = conn("203.0.113.5")
        named.domain = "dns.nextdns.io"
        self.assertTrue(is_doh(named))
        self.assertTrue(own_dns(proc(1, conns=[doh]), {}, watching_since=100))
        self.assertFalse(own_dns(proc(1, conns=[doh]), {}, watching_since=None))  # not watching: can't tell

    def test_inferred_from_unnamed_fresh_connections(self):
        from netapp_monitor.dns import own_dns
        conns = [conn(f"203.0.113.{i}", lport=50000 + i) for i in range(3)]
        p = proc(1, conns=conns)
        seen = {c.key: 200 for c in conns}
        self.assertTrue(own_dns(p, seen, watching_since=100, now=300))
        conns[0].domain = "example.com"
        self.assertFalse(own_dns(p, seen, watching_since=100, now=300))
        # Connections that were already open when watching began don't count.
        conns[0].domain = ""
        self.assertFalse(own_dns(p, {c.key: 50 for c in conns}, watching_since=100, now=300))


class AlwaysFileTest(unittest.TestCase):
    def test_empty_list_removes_file_so_the_service_stops(self):
        from netapp_monitor import blockctl
        with tempfile.TemporaryDirectory() as d, mock.patch.object(blockctl, "ALWAYS", f"{d}/always.json"):
            blockctl.save_always({"/usr/bin/x": {"since": 1, "uid": 1000}})
            self.assertEqual(list(blockctl.always_blocked()), ["/usr/bin/x"])
            blockctl.save_always({})
            self.assertFalse(Path(f"{d}/always.json").exists())
            blockctl.save_always({})  # already gone: fine
