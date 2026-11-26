"""The reader must not crash on garbage; it may reject, never raise."""
from __future__ import annotations

import json
import os
import random
import tempfile
import unittest

from tripwire import detect, logread


class GarbageInput(unittest.TestCase):
    def test_random_bytes_are_skipped_not_fatal(self):
        rng = random.Random(42)
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.log")
            with open(path, "wb") as fh:
                for _ in range(500):
                    fh.write(bytes(rng.randrange(256)
                                   for _ in range(rng.randrange(0, 80))))
                    fh.write(b"\n")
            rows, stats = logread.load_stats(path)
            self.assertIsInstance(rows, list)
            self.assertIsInstance(stats.get("skipped"), int)

    def test_random_json_objects_do_not_crash_analysis(self):
        rng = random.Random(7)
        values = [None, 0, -1, 1.5, "x", "", [], {}, True, "now", 10 ** 12]
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                for _ in range(300):
                    row = {key: rng.choice(values) for key in
                           ("ts", "ip", "ua", "method", "path", "status",
                            "auth", "referer", "query", "body")}
                    fh.write(json.dumps(row) + "\n")
            out = detect.watch(path, window=600, now=1_700_000_000)
            self.assertIn("rows", out)
            self.assertIsInstance(out.get("sessions"), dict)

    def test_a_line_at_the_size_cap_is_not_fatal(self):
        from tripwire import logread as lr
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.jsonl")
            big = "x" * (lr.MAX_LINE + 10)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": 1_700_000_000, "ip": "8.8.4.4",
                                     "path": "/" + big, "status": 200}) + "\n")
                fh.write(json.dumps({"ts": 1_700_000_001, "ip": "8.8.4.4",
                                     "path": "/ok", "status": 200}) + "\n")
            rows, stats = logread.load_stats(path)
            self.assertEqual(stats.get("oversize"), 1)
            self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
