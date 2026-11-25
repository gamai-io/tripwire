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
