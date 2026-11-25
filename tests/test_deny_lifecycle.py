"""The deny list must survive a quiet minute, expire, and refuse to grow wild."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest

from tripwire import cli, detect

NOW = 1795560000.0


def finding(ip, level="high", rules=("canary_used",), failures=0):
    return {"sessions": {ip: {"level": level, "points": 9,
                              "findings": [{"rule": r} for r in rules]}},
            "evidence": {ip: {"failures": failures}}}


class Lifecycle(unittest.TestCase):
    def test_a_quiet_run_does_not_lift_an_unexpired_block(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "deny.map")
            detect.write_deny_files(finding("8.8.4.4"), path, None, now=NOW, ttl_s=3600)
            self.assertIn("deny 8.8.4.4;", open(path).read())
            # a run that finds nothing must keep it
            detect.write_deny_files({"sessions": {}, "evidence": {}}, path, None,
                                    now=NOW + 60, ttl_s=3600)
            self.assertIn("deny 8.8.4.4;", open(path).read())

    def test_an_expired_block_is_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "deny.map")
            detect.write_deny_files(finding("8.8.4.4"), path, None, now=NOW, ttl_s=60)
            detect.write_deny_files({"sessions": {}, "evidence": {}}, path, None,
                                    now=NOW + 120, ttl_s=60)
            self.assertNotIn("deny 8.8.4.4;", open(path).read())

    def test_the_cap_refuses_instead_of_writing_a_huge_list(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "deny.map")
            result = {"sessions": {"8.8.%d.%d" % (i, i): {"level": "critical", "points": 10,
                                                          "findings": [{"rule": "canary_used"}]}
                                   for i in range(5)},
                      "evidence": {}}
            out = detect.write_deny_files(result, path, None, now=NOW, cap=2)
            self.assertIn("cap", out.get("error", ""))
            self.assertFalse(os.path.exists(path))

    def test_the_file_is_replaced_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "deny.map")
            detect.write_deny_files(finding("8.8.4.4"), path, None, now=NOW)
            leftovers = [n for n in os.listdir(td) if n.startswith(".deny-")]
            self.assertEqual(leftovers, [])


class ExitCodes(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(list(argv))
        return code, out.getvalue()

    def test_a_missing_log_is_three_not_clean(self) -> None:
        code, out = self.run_cli("watch", "--log", "/nonexistent/access.log")
        self.assertEqual(code, 3)
        self.assertIn("Unreadable", out)

    def test_an_empty_log_is_three(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.log")
            open(path, "w").close()
            code, out = self.run_cli("watch", "--log", path)
            self.assertEqual(code, 3)
            self.assertIn("no rows", out)

    def test_a_corrupt_registry_is_four_not_no_canaries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            reg = os.path.join(td, "c.json")
            open(reg, "w").write("{broken")
            log = os.path.join(td, "a.jsonl")
            with open(log, "w") as fh:
                fh.write(json.dumps({"ts": 1, "ip": "8.8.4.4", "path": "/x",
                                     "status": 200}) + "\n")
            code, out = self.run_cli("watch", "--log", log, "--registry", reg)
            self.assertEqual(code, 4)
            self.assertIn("RegistryError", out)

    def test_check_refuses_a_corrupt_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            reg = os.path.join(td, "c.json")
            open(reg, "w").write("{broken")
            code, _ = self.run_cli("check", "--token", "tw_x", "--registry", reg)
            self.assertEqual(code, 4)

    def test_a_finding_exits_one_and_torn_lines_are_counted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.log")
            with open(log, "w") as fh:
                fh.write('203.0.113.9 - - [25/Nov/2026:00:00:22 +0100] "GET /docs/api.md HTTP/1.1" 200 1 "-" "curl/8.7.1"\n')
                fh.write("this line is torn\n")
                for i in range(5):
                    fh.write('203.0.113.9 - - [25/Nov/2026:00:00:%02d +0100] "GET /x HTTP/1.1" 401 1 "-" "curl/8.7.1"\n' % (30 + i))
            code, out = self.run_cli("watch", "--log", log, "--window", "86400")
            self.assertEqual(code, 1)
            payload = json.loads(out)
            self.assertEqual(payload["skipped_lines"], 1)
            self.assertEqual(payload["rows"], 6)


if __name__ == "__main__":
    unittest.main()
