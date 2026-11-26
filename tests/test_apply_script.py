"""The root apply script must never leave a bad list in nginx.

Runs the real script with a fake `nginx`; no root and no nginx needed.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging" / "tripwire-apply-nginx.sh"


@unittest.skipUnless(os.name == "posix", "the apply script is POSIX shell")
class ApplyScript(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.td.name)
        self.src = self.dir / "deny.conf"
        self.dst = self.dir / "installed.conf"
        self.reloads = self.dir / "reloads"
        self.fake = self.dir / "nginx"
        self.fake.write_text(
            '#!/bin/sh\n'
            'if [ "$1" = "-t" ]; then\n'
            '  if grep -q "bad" "$CONF"; then exit 1; fi\n'
            '  exit 0\n'
            'fi\n'
            'echo reload >> "%s"\n'
            'exit 0\n' % self.reloads,
            encoding="utf-8")
        self.fake.chmod(0o755)

    def tearDown(self):
        self.td.cleanup()

    def _run(self):
        env = dict(os.environ, SRC=str(self.src), DST=str(self.dst),
                   NGINX=str(self.fake), CONF=str(self.dst))
        return subprocess.run(["sh", str(SCRIPT)], env=env,
                              capture_output=True, text=True)

    def test_a_rejected_list_restores_the_previous_file(self):
        self.dst.write_text("# good old list\ndeny 1.1.1.1;\n", encoding="utf-8")
        self.src.write_text("# bad new list\ndeny 2.2.2.2;\n", encoding="utf-8")
        done = self._run()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("1.1.1.1", self.dst.read_text())
        self.assertNotIn("2.2.2.2", self.dst.read_text())
        self.assertFalse(self.reloads.exists(), "nginx was reloaded with a bad list")

    def test_a_good_list_is_installed_and_reloaded_once(self):
        self.dst.write_text("# old\ndeny 1.1.1.1;\n", encoding="utf-8")
        self.src.write_text("# new\ndeny 2.2.2.2;\n", encoding="utf-8")
        first = self._run()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("2.2.2.2", self.dst.read_text())
        self.assertEqual(self.reloads.read_text().count("reload"), 1)
        second = self._run()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.reloads.read_text().count("reload"), 1,
                         "an unchanged list was reloaded")


if __name__ == "__main__":
    unittest.main()
