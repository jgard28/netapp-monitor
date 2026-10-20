import os
import unittest

from netapp_monitor import blockctl


class BlockctlTest(unittest.TestCase):
    def test_descendants(self):
        kids = {10: [11, 12], 11: [13], 99: [100]}
        self.assertEqual(sorted(blockctl.with_descendants([10], kids)), [10, 11, 12, 13])

    def test_children_map_includes_self(self):
        kids = blockctl.children_map()
        self.assertIn(os.getpid(), kids.get(os.getppid(), []))

    def test_ruleset_targets_cgroup_and_spares_loopback(self):
        self.assertIn(f'cgroupv2 level 1 "{blockctl.CGROUP_NAME}"', blockctl.RULESET)
        self.assertIn('oifname != "lo"', blockctl.RULESET)

    def test_cgroup_of_self(self):
        self.assertTrue(blockctl.cgroup_of(os.getpid()).startswith("/"))

    def test_restore_prefers_recorded_origin(self):
        state = {str(os.getpid()): {"origin": "/some/scope"}}
        first = next(blockctl.restore_candidates(os.getpid(), state, os.getuid()))
        self.assertEqual(first, blockctl.CGROUP_ROOT + "/some/scope")

    def test_restore_unrecorded_follows_parent(self):
        # A process the app spawned while blocked has no origin: it goes where its parent lives.
        first = next(blockctl.restore_candidates(os.getpid(), {}, os.getuid()))
        self.assertEqual(first, blockctl.CGROUP_ROOT + blockctl.cgroup_of(os.getppid()))

    def test_refuses_without_root(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        with self.assertRaises(SystemExit):
            blockctl.main(["block", str(os.getpid())])


if __name__ == "__main__":
    unittest.main()
