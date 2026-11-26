"""The deny list is nginx config; a real nginx must accept it.

`nginx -t` is the only honest check of the generated syntax; the unit tests can
prove escaping but not that nginx parses the file the way we think.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest

from tripwire import detect

BASE = 1_795_560_000.0
NGINX = shutil.which("nginx") or (
    "/usr/sbin/nginx" if os.path.exists("/usr/sbin/nginx") else None)


@unittest.skipUnless(NGINX, "nginx is not installed")
class NginxAccepts(unittest.TestCase):
    def _check(self, config_body: str) -> subprocess.CompletedProcess:
        td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, td, True)
        deny = os.path.join(td, "deny.conf")
        with open(deny, "w", encoding="utf-8") as fh:
            fh.write(config_body)
        conf = os.path.join(td, "nginx.conf")
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write("events {}\nhttp {\n  include %s;\n  server { listen 127.0.0.1:18080; }\n}\n"
                     % deny)
        return subprocess.run([NGINX, "-t", "-p", td, "-c", conf],
                              capture_output=True, text=True)

    def test_a_generated_list_parses(self) -> None:
        result = {"sessions": {
            "8.8.4.4": {"level": "high", "points": 9,
                        "findings": [{"rule": "canary_used"}]},
            "1.1.1.1": {"level": "critical", "points": 10,
                        "findings": [{"rule": "auth_failure_streak"}]}},
            "evidence": {}}
        out = detect.deny_list(result)
        self.assertIn("deny 8.8.4.4;", out["nginx"])
        done = self._check(out["nginx"])
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_reason_with_a_newline_cannot_break_the_config(self) -> None:
        result = {"sessions": {"8.8.4.4": {
            "level": "high", "points": 9,
            "findings": [{"rule": "canary_used",
                          "detail": "x\n}\nserver { listen 80; }"}]}},
            "evidence": {}}
        out = detect.deny_list(result)
        done = self._check(out["nginx"])
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
