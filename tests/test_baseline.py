"""Per-path baselines: a distributed scan must not look like a busy Tuesday."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from tripwire import baseline, detect

BASE = 1_795_560_000.0


def row(ip, ts, path="/api/v1/invoices", status=200, ua="curl/8.7.1"):
    return {"ts": ts, "ip": ip, "ua": ua, "method": "GET", "path": path,
            "status": status, "auth": "k", "referer": "", "ua_platform": "desktop"}


def window(count_ips, per_ip=2, path="/api/v1/invoices", start=BASE, status=404):
    rows = []
    for i in range(count_ips):
        for j in range(per_ip):
            rows.append(row("198.51.100.%d" % (i % 250), start + i * 0.5 + j,
                            path=path, status=status))
    return rows


class Template(unittest.TestCase):
    def test_numbers_and_uuids_become_placeholders(self) -> None:
        self.assertEqual(baseline.template("/api/v1/invoices/8812"),
                         "/api/v1/invoices/{}")
        self.assertEqual(baseline.template("/u/3f2a9c1b-77aa-4c1d-9e0f-ab12cd34ef56"),
                         "/u/{}")
        self.assertEqual(baseline.template("/pricing?x=1"), "/pricing")

    def test_a_real_word_is_not_a_placeholder(self) -> None:
        self.assertEqual(baseline.template("/api/v1/invoices"), "/api/v1/invoices")

    def test_static_assets_are_skipped(self) -> None:
        self.assertTrue(baseline.skip("/static/app.js"))
        self.assertFalse(baseline.skip("/api/v1/invoices"))


class History(unittest.TestCase):
    def test_a_cold_path_is_not_an_alarm(self) -> None:
        self.assertEqual(baseline.anomalies(window(40), baseline.load(""), floor_ips=10), [])

    def test_after_a_few_clean_windows_a_burst_is_an_alarm(self) -> None:
        history = baseline.load("")
        for _ in range(5):
            baseline.update(window(5, per_ip=4, status=200), history)
        found = baseline.anomalies(window(60), history, factor=3.0, floor_ips=10)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["path"], "/api/v1/invoices")
        self.assertGreater(found[0]["factor"], 3)

    def test_a_normal_window_is_quiet(self) -> None:
        history = baseline.load("")
        for _ in range(5):
            baseline.update(window(20, per_ip=3, status=200), history)
        self.assertEqual(baseline.anomalies(window(20, per_ip=3), history), [])

    def test_an_anomalous_window_does_not_poison_the_history(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "baseline.json")
            for i in range(4):
                rows = window(5, per_ip=4, status=200, start=BASE - 100 + i * 10)
                detect.watch_rows(rows, baseline_path=path, baseline_floor=10)
            saved = json.load(open(path))
            before = saved["paths"]["/api/v1/invoices"]["ips"]
            detect.watch_rows(window(80), baseline_path=path, baseline_floor=10)
            after = json.load(open(path))["paths"]["/api/v1/invoices"]["ips"]
            self.assertEqual(before, after)

    def test_writing_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "baseline.json")
            baseline.save(path, {"version": 1, "paths": {"/x": {"ips": 1}}, "samples": 1})
            self.assertEqual([n for n in os.listdir(td) if n.startswith(".baseline-")], [])


class EndToEnd(unittest.TestCase):
    def test_the_distributed_scan_is_reported_through_watch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            state = os.path.join(td, "baseline.json")

            def run(rows):
                with open(log, "w") as fh:
                    for item in rows:
                        fh.write(json.dumps(item) + "\n")
                return detect.watch(log, window=10 ** 9, baseline_path=state,
                                    baseline_floor=10)

            for i in range(4):
                result = run(window(5, per_ip=4, status=200, start=BASE - 100 + i * 10))
                self.assertEqual(result["path_anomalies"], [])
            result = run(window(70, start=BASE))
            self.assertEqual(len(result["path_anomalies"]), 1)
            self.assertIn("70 sources", result["path_anomalies"][0]["detail"])

    def test_the_alarm_goes_into_the_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            state = os.path.join(td, "baseline.json")
            ledger = os.path.join(td, "alerts.jsonl")
            for i in range(4):
                rows = window(5, per_ip=4, status=200, start=BASE - 100 + i * 10)
                with open(log, "w") as fh:
                    for item in rows:
                        fh.write(json.dumps(item) + "\n")
                detect.watch(log, window=10 ** 9, baseline_path=state, baseline_floor=10)
            rows = window(70, start=BASE)
            with open(log, "w") as fh:
                for item in rows:
                    fh.write(json.dumps(item) + "\n")
            detect.watch(log, window=10 ** 9, baseline_path=state,
                         baseline_floor=10, ledger=ledger)
            body = json.loads(open(ledger).read().strip().splitlines()[-1])["body"]
            self.assertEqual(body["kind"], "path_anomaly")

    def test_a_path_anomaly_obeys_the_level_filter(self) -> None:
        """It used to write to the ledger even at --min-level critical."""
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            state = os.path.join(td, "baseline.json")
            ledger = os.path.join(td, "alerts.jsonl")
            for i in range(4):
                rows = window(5, per_ip=4, status=200, start=BASE - 100 + i * 10)
                with open(log, "w") as fh:
                    for item in rows:
                        fh.write(json.dumps(item) + "\n")
                detect.watch(log, window=10 ** 9, baseline_path=state, baseline_floor=10)
            rows = window(70, start=BASE)
            with open(log, "w") as fh:
                for item in rows:
                    fh.write(json.dumps(item) + "\n")
            detect.watch(log, window=10 ** 9, baseline_path=state,
                         baseline_floor=10, ledger=ledger,
                         min_level="critical")
            self.assertFalse(os.path.exists(ledger),
                             "a high-severity path anomaly was written at "
                             "min-level critical")


if __name__ == "__main__":
    unittest.main()
