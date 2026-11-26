"""Time handling, empty logs, and a canary that arrives alone."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest

from tripwire import canary, detect, logread

LINE = ('203.0.113.9 - - [25/Nov/2026:00:00:22 +0100] "GET /docs/api.md HTTP/1.1" '
        '200 10 "-" "curl/8.7.1"\n')


class Timezone(unittest.TestCase):
    def test_the_reported_epoch_does_not_depend_on_the_host_zone(self) -> None:
        # 2026-11-24T23:00:22Z, whatever TZ the runner is in
        self.assertEqual(logread.parse_combined(LINE)["ts"], 1795561222.0)

    def test_a_negative_offset_is_applied_in_the_right_direction(self) -> None:
        line = LINE.replace("+0100", "-0500")
        self.assertEqual(logread.parse_combined(line)["ts"], 1795561222.0 + 6 * 3600)


class HistoricalLogs(unittest.TestCase):
    def test_a_log_older_than_the_window_is_still_analysed(self) -> None:
        second = ('203.0.113.9 - - [25/Nov/2026:00:00:32 +0100] "GET /api/v1/x HTTP/1.1" '
                  '401 10 "https://example/docs/api.md" "curl/8.7.1"\n')
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "access.log")
            with open(path, "w") as fh:
                fh.write(LINE)
                fh.write(second)
            res = detect.watch(path, window=600)
            self.assertEqual(res["rows"], 2)
            self.assertGreaterEqual(res["sessions"]["203.0.113.9"]["points"], 3)

    def test_wall_clock_still_works_when_asked_for(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "access.log")
            with open(path, "w") as fh:
                fh.write(LINE)
            res = detect.watch(path, None, window=600, now=time.time())
            self.assertEqual(res["sessions"], {})
            self.assertEqual(res["rows"], 1)


class CanaryAlone(unittest.TestCase):
    def test_a_single_line_with_a_canary_opens_a_case(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            reg = os.path.join(td, "c.json")
            token = canary.generate(1, path=reg)["tokens"][0]
            path = os.path.join(td, "a.jsonl")
            with open(path, "w") as fh:
                # a real epoch (2020) that the window still excludes; ts=1.0 is now
                # refused by logread.sane_epoch as an impossible timestamp
                fh.write(json.dumps({"ts": 1_600_000_000.0, "ip": "8.8.4.4",
                                     "ua": "curl/8.7.1",
                                     "method": "GET", "path": "/x", "status": 200,
                                     "auth": token}) + "\n")
            # a window that excludes the row: the canary must still be reported
            res = detect.watch(path, canary.load(path.replace("a.jsonl", "c.json")),
                               window=1, now=100.0)
            self.assertEqual(res["flagged"], 1)
            self.assertEqual(len(res["canary_hits"]), 1)
            self.assertEqual(res["sessions"]["8.8.4.4"]["level"], "critical")


class Empty(unittest.TestCase):
    def test_an_empty_file_reports_empty_not_clean(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "access.log")
            open(path, "w").close()
            res = detect.watch(path)
            self.assertTrue(res["empty"])
            self.assertEqual(res["sources"], 0)


if __name__ == "__main__":
    unittest.main()
