"""Randomised invariants for the window and the state file.

Not a formal proof: these are properties that must hold for any input the rules
claim to implement.
"""
from __future__ import annotations

import json
import os
import random
import tempfile
import unittest

from tripwire import detect

BASE = 1_795_560_000.0


def rows(seed: int, count: int = 120, now: float = BASE + 3600):
    rng = random.Random(seed)
    out = []
    for _ in range(count):
        out.append({
            "ts": now - rng.randrange(0, 7200),
            "ip": "198.51.100.%d" % rng.randrange(1, 40),
            "ua": rng.choice(["curl/8.7.1", "Mozilla/5.0 (X11) Chrome/157",
                              "Mozilla/5.0 (Linux; Android 15) Mobile",
                              "Googlebot/2.1"]),
            "method": rng.choice(["GET", "POST"]),
            "path": "/p/%d" % rng.randrange(1, 12),
            "status": rng.choice([200, 200, 200, 401, 403, 404]),
            "auth": "k",
        })
    return out


class WindowInvariants(unittest.TestCase):
    def test_no_session_comes_from_a_row_outside_the_window(self):
        for seed in range(30):
            data = rows(seed)
            now = BASE + 3600
            window = 600
            out = detect.analyse(data, window=window, now=now)
            in_window = {r["ip"] for r in data
                         if now - float(r["ts"]) <= window
                         and float(r["ts"]) <= now + 300}
            self.assertTrue(set(out["sessions"]).issubset(in_window), seed)

    def test_old_rows_do_not_change_a_windowed_result(self):
        for seed in range(30):
            data = rows(seed)
            now = BASE + 3600
            before = detect.analyse(data, window=600, now=now)
            old = [dict(r, ts=now - 10 ** 6 - i) for i, r in enumerate(data)]
            after = detect.analyse(data + old, window=600, now=now)
            self.assertEqual(before["flagged"], after["flagged"], seed)
            self.assertEqual(
                {ip: s["level"] for ip, s in before["sessions"].items()},
                {ip: s["level"] for ip, s in after["sessions"].items()}, seed)


class StateInvariants(unittest.TestCase):
    def test_a_second_identical_run_is_not_new(self):
        for seed in range(20):
            with tempfile.TemporaryDirectory() as td:
                log = os.path.join(td, "a.jsonl")
                state = os.path.join(td, "s.json")
                data = rows(seed, 80)
                with open(log, "w", encoding="utf-8") as fh:
                    for item in data:
                        fh.write(json.dumps(item) + "\n")
                first = detect.watch(log, window=10 ** 9, now=BASE + 4000,
                                     state_path=state, min_level="low")
                second = detect.watch(log, window=10 ** 9, now=BASE + 4000,
                                      state_path=state, min_level="low")
                self.assertEqual(second.get("new_alerts"), 0, seed)
                self.assertEqual(first["sessions"].keys(),
                                 second["sessions"].keys(), seed)


class StreamInvariants(unittest.TestCase):
    def test_a_chunk_larger_than_the_file_equals_batch(self):
        for seed in range(20):
            with tempfile.TemporaryDirectory() as td:
                log = os.path.join(td, "a.jsonl")
                data = rows(seed, 60)
                with open(log, "w", encoding="utf-8") as fh:
                    for item in data:
                        fh.write(json.dumps(item) + "\n")
                batch = detect.watch(log, window=10 ** 9, now=BASE + 4000)
                stream = detect.watch_stream(log, window=10 ** 9, chunk=10 ** 6,
                                             now=BASE + 4000)
                self.assertEqual(batch["flagged"], stream["flagged"], seed)
                self.assertEqual(
                    {ip: s["level"] for ip, s in batch["sessions"].items()},
                    {ip: s["level"] for ip, s in stream["sessions"].items()},
                    seed)


if __name__ == "__main__":
    unittest.main()
