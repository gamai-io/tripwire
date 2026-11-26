"""Regressions from the fifth review (RT5)."""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import tempfile
import time
import unittest
from unittest import mock

from tripwire import canary, detect

BASE = 1_795_560_000.0


def write(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for item in rows:
            fh.write(json.dumps(item) + "\n")


def row(ip, ts, path="/x", status=200):
    return {"ts": ts, "ip": ip, "ua": "curl/8.7.1", "method": "GET",
            "path": path, "status": status, "auth": "k"}


class SourceCapCannotBeBypassed(unittest.TestCase):
    def test_a_canary_outside_the_window_still_counts_against_the_cap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            registry = os.path.join(td, "can.json")
            token = canary.generate(count=1, path=registry)["tokens"][0]
            log = os.path.join(td, "a.jsonl")
            write(log, [row("198.51.100.1", BASE + 100),
                        row("198.51.100.2", BASE, "/" + token)])
            out = detect.watch_stream(log, canary.load(registry), window=10,
                                      max_sources=1)
            self.assertIn("too many distinct sources", out.get("error", ""))
            self.assertLessEqual(len(out["sessions"]), 1)

    def test_batch_refusal_reports_the_real_session_count(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            write(log, [row("198.51.100.%d" % i, BASE + i) for i in range(30)])
            out = detect.watch(log, window=10 ** 9, now=BASE + 31, max_sources=10)
            self.assertEqual(out["sources"], 30)


class RefusalHasNoSideEffects(unittest.TestCase):
    def test_the_baseline_is_not_updated_when_the_run_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            baseline = os.path.join(td, "baseline.json")
            write(log, [row("198.51.100.%d" % (i % 2), BASE + i) for i in range(20)])
            detect.watch(log, window=10 ** 9, now=BASE + 30,
                         baseline_path=baseline, baseline_floor=1)
            before = open(baseline, "rb").read()
            write(log, [row("198.51.100.%d" % i, BASE + 100 + i) for i in range(30)])
            out = detect.watch(log, window=10 ** 9, now=BASE + 200,
                               max_sources=10, baseline_path=baseline,
                               baseline_floor=1)
            self.assertIn("too many distinct sources", out.get("error", ""))
            self.assertEqual(open(baseline, "rb").read(), before,
                             "a refused run changed the baseline")


class StreamHonoursNow(unittest.TestCase):
    def test_a_future_log_can_be_replayed_with_now(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            future = time.time() + 600
            write(log, [row("198.51.100.1", future + i, status=401)
                        for i in range(3)])
            batch = detect.watch(log, window=1200, now=future + 10)
            stream = detect.watch_stream(log, window=1200, now=future + 10)
            self.assertEqual(stream.get("error"), None)
            self.assertEqual(batch["rows_in_window"], stream["rows_in_window"])


class DenyCommentsAreClean(unittest.TestCase):
    def test_an_approver_newline_cannot_inject_config(self) -> None:
        result = {"sessions": {"8.8.4.4": {
            "level": "critical", "points": 10,
            "findings": [{"rule": "canary_used"}],
            "exception": {"until": 9999999999,
                          "approver": "ops)\nallow all; #", "reason": "x"}}},
            "evidence": {}}
        text = detect.deny_list(result, now=time.time())["nginx"]
        for line in text.splitlines():
            self.assertFalse(line.strip().startswith("allow all"),
                             "an injected nginx directive reached the file")
        self.assertEqual(text.count("\nallow all"), 0)


def _worker(path, ip):
    time.sleep(0.001)
    result = {"sessions": {ip: {"level": "critical", "points": 10,
                                "findings": [{"rule": "canary_used"}]}},
              "evidence": {}}
    detect.write_deny_files(result, path, None, now=time.time())


class ConcurrentWriters(unittest.TestCase):
    def test_two_writers_do_not_lose_an_entry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "deny.map")
            processes = [mp.Process(target=_worker, args=(path, "8.8.8.1")),
                         mp.Process(target=_worker, args=(path, "8.8.8.2"))]
            for proc in processes:
                proc.start()
            for proc in processes:
                proc.join()
            text = open(path).read()
            self.assertIn("deny 8.8.8.1;", text)
            self.assertIn("deny 8.8.8.2;", text)


class PartialCommit(unittest.TestCase):
    def test_a_failed_map_replace_leaves_the_json_untouched(self) -> None:
        result = {"sessions": {"8.8.4.4": {"level": "critical", "points": 10,
                                           "findings": [{"rule": "canary_used"}]}},
                  "evidence": {}}
        with tempfile.TemporaryDirectory() as td:
            deny_map = os.path.join(td, "deny.map")
            deny_json = os.path.join(td, "deny.json")
            with mock.patch("tripwire.detect.os.replace",
                            side_effect=OSError("simulated map failure")):
                out = detect.write_deny_files(result, deny_map, deny_json,
                                              now=time.time())
            self.assertIn("error", out)
            self.assertFalse(os.path.exists(deny_map))
            self.assertFalse(os.path.exists(deny_json),
                             "JSON was written before the map replace failed")


class HugeTimestamp(unittest.TestCase):
    def test_an_unrepresentable_epoch_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"ts":1' + "0" * 309 +
                         ',"ip":"8.8.4.4","path":"/x","status":200}\n')
            out = detect.watch(path, window=600)
            self.assertEqual(out["skipped_lines"], 1)


if __name__ == "__main__":
    unittest.main()
