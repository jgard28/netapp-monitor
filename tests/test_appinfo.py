import gzip
import hashlib
import subprocess
import os
import shutil
import sys
import tempfile
import unittest

from netapp_monitor import appinfo
from netapp_monitor.collector import HIGH, Process


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


class IntegrityTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.exe = os.path.join(self.root, "my app")  # a space exercises mtree escaping
        with open(self.exe, "wb") as f:
            f.write(b"original")
        db = os.path.join(self.root, "db")
        os.makedirs(f"{db}/demo-1.0-1")
        digest = hashlib.sha256(b"original").hexdigest()
        escaped = self.exe.replace(" ", "\\040")
        with gzip.open(f"{db}/demo-1.0-1/mtree", "wt") as f:
            f.write("#mtree\n/set type=file\n")
            f.write(f".{escaped} time=1.0 size=8 sha256digest={digest}\n")
        self.saved = appinfo.PACMAN_DB
        appinfo.PACMAN_DB = db

    def tearDown(self):
        appinfo.PACMAN_DB = self.saved

    def test_packaged_hash_found(self):
        self.assertEqual(appinfo.packaged_hash(self.exe, "demo 1.0-1"),
                         ("sha256", hashlib.sha256(b"original").hexdigest()))
        self.assertIsNone(appinfo.packaged_hash("/elsewhere", "demo 1.0-1"))

    def test_tampered_exe_raises_high_alert(self):
        loader = appinfo.AppInfoLoader()
        loader.cache[loader._key(self.exe)] = {"package": "demo 1.0-1", "sha256": "x", "exe_matches": False}
        alert = loader.alert_for(Process(1, "my app", self.exe))
        self.assertEqual((alert.severity, alert.kind), (HIGH, "never-mute"))

    def test_verify_parses_pacman_output(self):
        sample = subprocess.CompletedProcess([], 0, stdout="demo: 10 total files, 2 altered files\n", stderr=(
            "warning: demo: /usr/bin/demo (SHA256 checksum mismatch)\n"
            "warning: demo: /usr/lib/demo.so (Size mismatch)\n"
            "warning: demo: /usr/share/demo/secret (Permission denied)\n"
            "warning: demo: /usr/share/doc/demo (Modification time mismatch)\n"))
        saved = appinfo._run
        appinfo._run = lambda *a, **k: sample
        try:
            if not shutil.which("pacman"):
                self.skipTest("pacman not installed")
            result = appinfo.verify_package("demo 1.0-1")
        finally:
            appinfo._run = saved
        self.assertEqual(result["files"], 10)
        self.assertEqual([p for p, _ in result["changed"]], ["/usr/bin/demo", "/usr/lib/demo.so"])
        self.assertEqual(result["unreadable"], 1)


if __name__ == "__main__":
    unittest.main()
