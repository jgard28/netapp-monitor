import hashlib
import os
import shutil
import sys
import tempfile
import unittest

from netapp_monitor import appinfo


class AppInfoTest(unittest.TestCase):
    def test_sha256(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"netapp")
        self.assertEqual(appinfo.sha256(f.name), hashlib.sha256(b"netapp").hexdigest())
        os.unlink(f.name)

    @unittest.skipUnless(shutil.which("pacman") or shutil.which("dpkg") or shutil.which("rpm"), "no package manager")
    def test_owning_package(self):
        self.assertIsNotNone(appinfo.owning_package(os.path.realpath(sys.executable)))
        self.assertIsNone(appinfo.owning_package(tempfile.gettempdir() + "/definitely-not-packaged"))

    def test_parent_chain_starts_with_parent(self):
        chain = appinfo.parent_chain(os.getpid())
        self.assertEqual(chain[0][1], os.getppid())


if __name__ == "__main__":
    unittest.main()
