"""Streaming: bounded memory over a file that never fits, same verdicts."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from tripwire import canary, detect

BASE = 1_795_560_000.0
DESKTOP = "Mozilla/5.0 (Macintosh) Chrome/157.0"
PHONE = "Mozilla/5.0 (Linux; Android 15) Mobile"
CURL = "curl/8.7.1"


def row(ts, ip, ua, path, status=200, auth="none", referer=""):
    return {"ts": ts, "ip": ip, "ua": ua, "method": "GET", "path": path,
            "status": status, "auth": auth, "referer": referer,
            "ua_platform": "mobile" if "Mobile" in ua else "desktop"}


def noise(start, count, ip="203.0.113.5"):
    return [row(start + i, ip, DESKTOP, "/pricing", 200) for i in range(count)]


def incident(start, ip="198.51.100.9"):
    return [row(start, ip, DESKTOP, "/", 403),
            row(start + 6, ip, PHONE, "/", 403),
            row(start + 16, ip, DESKTOP, "/decoy/openapi.md"),
            row(start + 29, ip, DESKTOP, "/api/v1/transactions",
                referer="/decoy/openapi.md"),
            row(start + 40, ip, CURL, "/api/v1/transactions", 401, auth="key-A"),
            row(start + 42, ip, CURL, "/api/v1/transactions", 401, auth="none"),
            row(start + 44, ip, CURL, "/api/v1/transactions", 401, auth="made-up")]


def write(rows):
    path = tempfile.mkstemp(suffix=".jsonl")[1]
    with open(path, "w") as fh:
        for item in rows:
            fh.write(json.dumps(item) + "\n")
    return path


class Stream(unittest.TestCase):
    def tearDown(self) -> None:
        for path in self.paths:
            if os.path.exists(path):
                os.remove(path)

    def setUp(self) -> None:
        self.paths = []

    def _run(self, rows, chunk=50):
        path = write(rows)
        self.paths.append(path)
        return detect.watch_stream(path, window=10 ** 9, chunk=chunk)

    def test_the_incident_is_still_high_when_scored_in_chunks(self) -> None:
        rows = noise(BASE, 500) + incident(BASE + 600) + noise(BASE + 700, 500)
        result = self._run(rows, chunk=100)
        self.assertEqual(result["sessions"]["198.51.100.9"]["level"], "high")
        self.assertTrue(result["stream"])

    def test_benign_traffic_stays_low(self) -> None:
        result = self._run(noise(BASE, 2000), chunk=200)
        self.assertEqual(result["flagged"], 0)

    def test_a_canary_is_found_at_the_end_of_a_large_file(self) -> None:
        reg = tempfile.mkstemp(suffix=".json")[1]
        self.paths.append(reg)
        token = canary.generate(1, path=reg)["tokens"][0]
        rows = noise(BASE, 5000) + [row(BASE + 9000, "198.51.100.9", CURL,
                                       "/api/v1/x", 200, auth=token)]
        path = write(rows)
        self.paths.append(path)
        result = detect.watch_stream(path, canary.load(reg), window=10 ** 9, chunk=500)
        self.assertEqual(len(result["canary_hits"]), 1)
        self.assertEqual(result["sessions"]["198.51.100.9"]["level"], "critical")

    def test_memory_is_bounded_by_the_window_not_the_file(self) -> None:
        rows = noise(BASE, 20000)
        result = self._run(rows, chunk=1000)
        self.assertLessEqual(result["rows_in_window"], 2 * 1000 + 1000)
        self.assertEqual(result["rows"], 20000)

    def test_an_empty_file_is_reported_as_empty(self) -> None:
        path = write([])
        self.paths.append(path)
        self.assertTrue(detect.watch_stream(path)["empty"])


if __name__ == "__main__":
    unittest.main()
