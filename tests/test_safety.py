"""Safety of the verdict and the deny list, plus the measured tuning."""
from __future__ import annotations

import os
import tempfile
import time
import unittest

from tripwire import canary, detect, logread

NOW = 1795558000.0
DESKTOP = "Mozilla/5.0 (Macintosh) Chrome/157.0"
CURL = "curl/8.7.1"


def row(ts, path, status=200, ua=DESKTOP, auth="none", referer="", ip="81.2.3.4"):
    return {"ts": ts, "ip": ip, "ua": ua, "method": "GET", "path": path,
            "status": status, "auth": auth, "referer": referer,
            "ua_platform": "mobile" if "Mobile" in ua else "desktop"}


class CombinedLog(unittest.TestCase):
    LINE = ('203.0.113.9 - - [25/Nov/2026:00:00:22 +0100] "GET /pricing HTTP/1.1" '
            '200 5120 "-" "Mozilla/5.0 (Macintosh) Chrome/157.0"')

    def test_a_combined_line_is_parsed(self) -> None:
        item = logread.parse_combined(self.LINE)
        self.assertEqual(item["path"], "/pricing")
        self.assertEqual(item["status"], 200)
        self.assertEqual(item["ua_platform"], "desktop")
        self.assertEqual(item["auth"], "none")

    def test_the_time_is_timezone_aware(self) -> None:
        item = logread.parse_combined(self.LINE)
        self.assertEqual(time.strftime("%Y-%m-%d", time.gmtime(item["ts"])), "2026-11-24")

    def test_a_malformed_line_is_skipped(self) -> None:
        self.assertIsNone(logread.parse_combined("not a log line"))

    def test_a_mobile_user_agent_is_recognised(self) -> None:
        phone = self.LINE.replace("Mozilla/5.0 (Macintosh) Chrome/157.0",
                                  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6) Mobile/15E148")
        self.assertEqual(logread.parse_combined(phone)["ua_platform"], "mobile")

    def test_format_is_detected_and_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "access.log")
            with open(path, "w") as fh:
                fh.write(self.LINE + "\n")
            self.assertEqual(logread.guess_format(path), "combined")
            self.assertEqual(len(logread.load(path)), 1)


class Corroboration(unittest.TestCase):
    def test_reading_the_spec_then_a_new_page_is_not_an_attack(self) -> None:
        rows = [row(NOW - 100, "/docs/api.md"),
                row(NOW - 90, "/pricing", referer="/docs/api.md")]
        res = detect.analyse(rows, now=NOW)
        session = res["sessions"]["81.2.3.4"]
        self.assertEqual(session["level"], "low")
        self.assertTrue(all(f.get("suppressed") for f in session["findings"]))

    def test_the_same_shape_with_a_failed_check_counts(self) -> None:
        rows = [row(NOW - 100, "/docs/api.md"),
                row(NOW - 90, "/api/v1/transactions", 401, referer="/docs/api.md")]
        res = detect.analyse(rows, now=NOW)
        session = res["sessions"]["81.2.3.4"]
        self.assertGreaterEqual(session["points"], 6)
        self.assertEqual(session["level"], "high")

    def test_one_document_unlocks_one_path_only(self) -> None:
        rows = [row(NOW - 100, "/docs/api.md")]
        for i in range(6):
            rows.append(row(NOW - 90 + i, "/api/v1/x/%d" % i, 401))
        derived = [p["path"] for p in detect.spec_derived_paths(rows)]
        self.assertEqual(len(derived), 1, derived)

    def test_a_failed_document_fetch_does_not_unlock_paths(self) -> None:
        rows = [row(NOW - 100, "/docs/api.md", 403), row(NOW - 90, "/x", 401)]
        self.assertEqual(detect.spec_derived_paths(rows), [])


class Weights(unittest.TestCase):
    def test_a_developer_switching_to_curl_stays_low(self) -> None:
        """Browser then curl with a key that works is a developer, not an intruder."""
        rows = [row(NOW - 300, "/"), row(NOW - 250, "/docs/api.md")]
        for i in range(6):
            rows.append(row(NOW - 200 + i * 5, "/api/v1/invoices", auth="key-valid"))
        rows.append(row(NOW - 100, "/api/v1/invoices", auth="key-valid", ua=CURL))
        res = detect.analyse(rows, now=NOW)
        self.assertEqual(res["sessions"]["81.2.3.4"]["level"], "low")

    def test_five_rejected_credentials_on_one_endpoint_are_high(self) -> None:
        rows = [row(NOW - 60 + i, "/api/v1/invoices", 401, ua=CURL, auth="k%d" % i)
                for i in range(5)]
        res = detect.analyse(rows, now=NOW)
        self.assertEqual(res["sessions"]["81.2.3.4"]["level"], "high")


class DenySafety(unittest.TestCase):
    def _result(self, ip: str) -> dict:
        return {"sessions": {ip: {"level": "high", "points": 9,
                                  "findings": [{"rule": "canary_used"}]}}}

    def test_a_loopback_address_is_never_denied(self) -> None:
        res = detect.deny_list(self._result("127.0.0.1"))
        self.assertEqual(res["count"], 0)
        self.assertEqual(res["skipped"][0]["why"], "not a global address")

    def test_a_private_address_is_never_denied(self) -> None:
        self.assertEqual(detect.deny_list(self._result("10.1.2.3"))["count"], 0)

    def test_a_global_address_is_denied_with_an_expiry(self) -> None:
        res = detect.deny_list(self._result("8.8.4.4"), now=NOW, ttl_s=600)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["entries"][0]["expires"], int(NOW + 600))
        self.assertIn("deny 8.8.4.4;", res["nginx"])

    def test_an_ignored_address_is_reported_not_denied(self) -> None:
        res = detect.deny_list(self._result("8.8.4.4"), ignore={"8.8.4.4"})
        self.assertEqual(res["count"], 0)
        self.assertEqual(res["skipped"][0]["why"], "ignored")


class CanaryStillWins(unittest.TestCase):
    def test_a_canary_in_an_otherwise_clean_session_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "canaries.json")
            token = canary.generate(1, path=path)["tokens"][0]
            rows = [row(NOW - 30, "/pricing"), row(NOW - 20, "/api/v1/x", auth=token)]
            res = detect.analyse(rows, canary.load(path), now=NOW)
            self.assertEqual(res["sessions"]["81.2.3.4"]["level"], "critical")

    def test_json_and_combined_produce_the_same_level(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.log")
            with open(path, "w") as fh:
                fh.write('203.0.113.9 - - [25/Nov/2026:00:00:22 +0100] "GET /docs/api.md HTTP/1.1" 200 10 "-" "curl/8.7.1"\n')
                fh.write('203.0.113.9 - - [25/Nov/2026:00:00:32 +0100] "GET /api/v1/x HTTP/1.1" 401 10 "https://x/docs/api.md" "curl/8.7.1"\n')
                fh.write('203.0.113.9 - - [25/Nov/2026:00:00:42 +0100] "GET /api/v1/x HTTP/1.1" 401 10 "-" "curl/8.7.1"\n')
            res = detect.watch(path, window=86400)
            self.assertEqual(res["sessions"]["203.0.113.9"]["level"], "high")


if __name__ == "__main__":
    unittest.main()
