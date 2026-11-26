"""State: a cron must not shout about the same address every minute."""
from __future__ import annotations

import os
import tempfile
import unittest

from tripwire import detect

NOW = 1795558000.0


def result(level="high", points=8):
    return {"sessions": {"8.8.4.4": {"level": level, "points": points,
                                     "findings": [{"rule": "ua_flip"}]}},
            "evidence": {"8.8.4.4": {"failures": 9}}}


class State(unittest.TestCase):
    def test_the_second_run_marks_the_same_alert_as_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            first = detect.apply_state(result(), path, now=NOW)
            self.assertEqual(first["new_alerts"], 1)
            self.assertTrue(first["sessions"]["8.8.4.4"]["is_new"])
            second = detect.apply_state(result(), path, now=NOW + 60)
            self.assertEqual(second["new_alerts"], 0)
            self.assertTrue(second["sessions"]["8.8.4.4"]["repeat"])

    def test_an_escalation_is_new_again(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            detect.apply_state(result("medium", 4), path, now=NOW)
            out = detect.apply_state(result("critical", 12), path, now=NOW + 60)
            self.assertEqual(out["new_alerts"], 1)

    def test_after_the_ttl_it_is_new_again(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            detect.apply_state(result(), path, ttl_s=60, now=NOW)
            self.assertEqual(detect.apply_state(result(), path, ttl_s=60,
                                                now=NOW + 120)["new_alerts"], 1)

    def test_a_corrupt_state_file_does_not_crash_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            open(path, "w").write("{not json")
            self.assertEqual(detect.apply_state(result(), path, now=NOW)["new_alerts"], 1)

    def test_low_sessions_are_not_remembered(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state.json")
            out = detect.apply_state(result("low", 1), path, now=NOW)
            self.assertEqual(out["new_alerts"], 0)


if __name__ == "__main__":
    unittest.main()


class LedgerWrites(unittest.TestCase):
    def _log(self, ip="8.8.4.4"):
        import json
        import tempfile
        import time as _t
        td = tempfile.mkdtemp()
        path = os.path.join(td, "a.jsonl")
        now = _t.time() - 30
        rows = [
            {"ts": now, "ip": ip, "ua": "Mozilla/5.0 (Macintosh) Chrome/157",
             "method": "GET", "path": "/", "status": 403, "auth": "k"},
            {"ts": now + 1, "ip": ip, "ua": "Mozilla/5.0 (Linux; Android 15) Mobile",
             "method": "GET", "path": "/", "status": 403, "auth": "k"},
            {"ts": now + 2, "ip": ip, "ua": "curl/8.7.1", "method": "GET",
             "path": "/api", "status": 401, "auth": "k"},
        ]
        with open(path, "w") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        return td, path

    def test_a_repeat_does_not_write_a_second_alert(self) -> None:
        import os as _os

        from tripwire import detect
        td, path = self._log()
        ledger = _os.path.join(td, "alerts.jsonl")
        state = _os.path.join(td, "state.json")
        detect.watch(path, ledger=ledger, state_path=state, min_level="medium")
        detect.watch(path, ledger=ledger, state_path=state, min_level="medium")
        detect.watch(path, ledger=ledger, state_path=state, min_level="medium")
        lines = open(ledger).read().strip().splitlines()
        self.assertEqual(len(lines), 1, "a repeat wrote another alert")

    def test_min_level_filters_what_lands_in_the_ledger(self) -> None:
        import json
        import os as _os
        import tempfile
        import time as _t

        from tripwire import detect
        td = tempfile.mkdtemp()
        path = _os.path.join(td, "a.jsonl")
        now = _t.time() - 30
        rows = [
            {"ts": now, "ip": "8.8.4.4", "ua": "Mozilla/5.0 (Macintosh) Chrome/157",
             "method": "GET", "path": "/pricing", "status": 200, "auth": "k"},
            {"ts": now + 1, "ip": "8.8.4.4",
             "ua": "Mozilla/5.0 (Linux; Android 15) Mobile",
             "method": "GET", "path": "/pricing", "status": 200, "auth": "k"},
            {"ts": now + 2, "ip": "8.8.4.4", "ua": "curl/8.7.1", "method": "GET",
             "path": "/pricing", "status": 200, "auth": "k"},
        ]
        with open(path, "w") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        ledger = _os.path.join(td, "alerts.jsonl")
        res = detect.watch(path, ledger=ledger, min_level="high")
        self.assertEqual(res["sessions"]["8.8.4.4"]["level"], "medium")
        self.assertFalse(_os.path.exists(ledger),
                         "a medium alert was written at min-level high")
