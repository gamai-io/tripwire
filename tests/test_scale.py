"""One noisy address must not make the run quadratic."""
from __future__ import annotations

import time
import unittest

from tripwire import detect


def rows(n: int, paths: int = 1) -> list[dict]:
    base = 1_795_000_000.0
    return [{"ts": base + i * 0.01, "ip": "8.8.4.4", "ua": "curl/8.7.1",
             "method": "GET", "path": "/api/v1/invoices" if paths == 1 else "/p/%d" % (i % paths),
             "status": 401, "auth": "k%d" % (i % 3)} for i in range(n)]


class Scale(unittest.TestCase):
    def test_100k_requests_on_one_path_finish_quickly(self) -> None:
        batch = rows(100_000)
        start = time.perf_counter()
        result = detect.analyse(batch, now=batch[-1]["ts"] + 1, window=10 ** 9)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 10.0, "quadratic behaviour is back: %.1fs" % elapsed)
        self.assertEqual(result["sessions"]["8.8.4.4"]["level"], "high")

    def test_the_streak_is_still_counted_correctly(self) -> None:
        batch = rows(10)
        streaks = detect.auth_failure_streak(batch)
        self.assertEqual(len(streaks), 1)
        self.assertEqual(streaks[0]["attempts"], 10)

    def test_a_gap_longer_than_a_minute_breaks_the_streak(self) -> None:
        batch = rows(4)
        batch.append({**batch[-1], "ts": batch[-1]["ts"] + 120})
        self.assertEqual(len(detect.auth_failure_streak(batch)), 0)

    def test_path_burst_counts_distinct_paths_in_the_window(self) -> None:
        batch = rows(60, paths=60)
        self.assertEqual(len(detect.path_burst(batch)), 1)


if __name__ == "__main__":
    unittest.main()
