"""Regressions from the fourth review (RT4): stream semantics, partial writes."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest

from tripwire import detect

BASE = 1_795_560_000.0


def row(ip, ts, path="/api/v1/login", status=401, ua="curl/8.7.1"):
    return {"ts": ts, "ip": ip, "ua": ua, "method": "GET", "path": path,
            "status": status, "auth": "k"}


def write(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for item in rows:
            fh.write(json.dumps(item) + "\n")


class StreamWindowZero(unittest.TestCase):
    def test_stream_with_no_window_is_not_cleaner_than_batch(self) -> None:
        """window=0 means the whole file; trimming by zero used to hide streaks."""
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            write(log, [row("8.8.4.4", BASE + i) for i in range(6)])
            batch = detect.watch(log, window=0, now=BASE + 10)
            stream = detect.watch_stream(log, window=0, chunk=2, now=BASE + 10)
            self.assertEqual(batch["sessions"]["8.8.4.4"]["level"],
                             stream["sessions"]["8.8.4.4"]["level"])
            self.assertEqual(batch["flagged"], stream["flagged"])
            self.assertGreaterEqual(stream["rows_in_window"], 6)


class OutOfOrder(unittest.TestCase):
    def test_rows_older_than_the_window_do_not_stay_forever(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            now = time.time() - 100
            rows = [row("1.1.1.1", now + 90, "/ok", 200)]
            for i in range(5):
                rows.append(row("2.2.2.%d" % i, now - 1000 - i, "/old", 200))
            write(log, rows)
            out = detect.watch_stream(log, window=60, chunk=10)
            batch = detect.watch(log, window=60, now=now + 91)
            self.assertEqual(out["rows_in_window"], batch["rows_in_window"])
            self.assertEqual(out["rows_in_window"], 1)


class PartialDenyWrite(unittest.TestCase):
    def test_a_failed_json_write_does_not_swap_the_map(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            deny_map = os.path.join(td, "deny.conf")
            blocker = os.path.join(td, "blocker")
            open(blocker, "w").write("x")
            deny_json = os.path.join(blocker, "deny.json")  # parent is a file
            write(log, [row("8.8.4.4", BASE + i) for i in range(6)])
            result = {"sessions": {"8.8.4.4": {
                "level": "high", "points": 6,
                "findings": [{"rule": "auth_failure_streak", "points": 4}]}},
                "evidence": {}}
            out = detect.write_deny_files(result, deny_map, deny_json)
            self.assertIn("error", out)
            self.assertFalse(os.path.exists(deny_map),
                             "the map was swapped before the JSON write failed")


class StateSaveFailure(unittest.TestCase):
    def test_a_state_write_failure_is_reported_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            ledger = os.path.join(td, "alerts.jsonl")
            blocker = os.path.join(td, "blocker")
            open(blocker, "w").write("x")
            state = os.path.join(blocker, "state.json")
            write(log, [row("8.8.4.4", BASE + i) for i in range(6)])
            out = detect.watch(log, ledger=ledger, state_path=state,
                               now=BASE + 10)
            self.assertTrue(os.path.exists(ledger))
            self.assertIn("state_error", out)


class PathFingerprint(unittest.TestCase):
    def test_a_new_source_set_on_the_same_path_is_new(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            baseline = os.path.join(td, "b.json")
            state = os.path.join(td, "s.json")
            for i in range(4):
                rows = [row("198.51.100.%d" % (n % 250),
                            BASE - 100 + i * 10 + n * 0.1, status=200)
                        for n in range(5) for _ in range(4)]
                write(log, rows)
                detect.watch(log, window=10 ** 9, baseline_path=baseline,
                             baseline_floor=10, state_path=state,
                             now=BASE - 50 + i)
            write(log, [row("198.51.100.%d" % n, BASE + n * 0.1, status=404)
                        for n in range(20) for _ in range(2)])
            first = detect.watch(log, window=10 ** 9, baseline_path=baseline,
                                 baseline_floor=10, state_path=state,
                                 now=BASE + 100)
            self.assertEqual(len(first["new_path_anomalies"]), 1)
            write(log, [row("203.0.113.%d" % n, BASE + 200 + n * 0.1, status=404)
                        for n in range(20) for _ in range(2)])
            second = detect.watch(log, window=10 ** 9, baseline_path=baseline,
                                  baseline_floor=10, state_path=state,
                                  now=BASE + 200)
            self.assertEqual(len(second["new_path_anomalies"]), 1,
                             "a different source set was suppressed as a repeat")


if __name__ == "__main__":
    unittest.main()
