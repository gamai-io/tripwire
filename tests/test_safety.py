"""Safety of the verdict and the deny list, plus the measured tuning."""
from __future__ import annotations

import json
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


class PathBurst(unittest.TestCase):
    def _scan(self, ua, count=50, status=301):
        return [row(NOW - 60 + i, "/p/%d.php" % i, status, ua=ua) for i in range(count)]

    def test_a_redirect_heavy_scan_is_caught_without_any_4xx(self) -> None:
        rows = self._scan(CURL)
        res = detect.analyse(rows, now=NOW)
        session = res["sessions"]["81.2.3.4"]
        self.assertIn("path_burst", {f["rule"] for f in session["findings"]})
        self.assertGreaterEqual(session["points"], 3)

    def test_a_search_crawler_is_not_a_burst(self) -> None:
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        self.assertEqual(detect.path_burst(self._scan(ua)), [])

    def test_below_the_threshold_nothing_fires(self) -> None:
        self.assertEqual(detect.path_burst(self._scan(CURL, count=20)), [])


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

    def test_volume_evidence_alone_does_not_deny(self) -> None:
        result = {"sessions": {"8.8.4.4": {"level": "medium", "points": 4,
                                           "findings": [{"rule": "velocity"},
                                                        {"rule": "wide_probe"}]}},
                  "evidence": {"8.8.4.4": {"failures": 0}}}
        res = detect.deny_list(result)
        self.assertEqual(res["count"], 0)
        self.assertIn("volume", res["skipped"][0]["why"])

    def test_behaviour_alone_never_denies_a_shared_address(self) -> None:
        """A laptop, a phone and one curl script behind one NAT look like this."""
        result = {"sessions": {"8.8.4.4": {"level": "high", "points": 8,
                                           "findings": [{"rule": "ua_flip"},
                                                        {"rule": "tool_switch"}]}},
                  "evidence": {"8.8.4.4": {"failures": 0}}}
        out = detect.deny_list(result)
        self.assertEqual(out["count"], 0)
        self.assertIn("behaviour", out["skipped"][0]["why"])

    def test_identity_evidence_denies(self) -> None:
        result = {"sessions": {"8.8.4.4": {"level": "high", "points": 6,
                                           "findings": [{"rule": "auth_failure_streak"}]}},
                  "evidence": {"8.8.4.4": {"failures": 9}}}
        self.assertEqual(detect.deny_list(result)["count"], 1)

    def test_the_operator_can_opt_into_volume_denial(self) -> None:
        result = {"sessions": {"8.8.4.4": {"level": "medium", "points": 4,
                                           "findings": [{"rule": "velocity"}]}},
                  "evidence": {"8.8.4.4": {"failures": 0}}}
        self.assertEqual(detect.deny_list(result, allow_volume=True)["count"], 1)

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


class FutureAndGarbage(unittest.TestCase):
    def test_a_future_dated_line_does_not_blind_the_run(self) -> None:
        from tripwire import detect as d
        now = time.time()
        rows = [row(now - 60 + i, "/pricing") for i in range(50)]
        rows.append(row(now + 400 * 86400, "/", 403, ip="198.51.100.7"))
        result = d.analyse(rows, window=600, now=now)
        self.assertGreaterEqual(result["sources"], 1)
        self.assertNotIn("198.51.100.7", result["sessions"])

    def test_an_unparsable_status_does_not_crash_the_parser(self) -> None:
        line = ('203.0.113.9 - - [25/Nov/2026:00:00:22 +0100] "GET /x HTTP/1.1" '
                '- 10 "-" "curl/8.7.1"')
        self.assertIsNone(logread.parse_combined(line))

    def test_the_deny_list_merges_with_a_json_only_run(self) -> None:
        result = {"sessions": {"8.8.4.4": {"level": "critical", "points": 10,
                                           "findings": [{"rule": "canary_used"}]}},
                  "evidence": {}}
        with tempfile.TemporaryDirectory() as td:
            js = os.path.join(td, "deny.json")
            detect.write_deny_files(result, None, js, now=NOW)
            first = json.load(open(js))["deny"]
            self.assertEqual(len(first), 1)
            quiet = {"sessions": {}, "evidence": {}}
            detect.write_deny_files(quiet, None, js, now=NOW + 60)
            self.assertEqual(len(json.load(open(js))["deny"]), 1)


class Exceptions(unittest.TestCase):
    def test_an_active_exception_prevents_a_deny_and_says_who_allowed_it(self) -> None:
        result = {"sessions": {"8.8.4.4": {"level": "critical", "points": 10,
                                           "findings": [{"rule": "canary_used"}]}},
                  "evidence": {}}
        exceptions = [{"ip": "8.8.4.4", "until": int(NOW) + 3600,
                       "approver": "ops", "reason": "our scanner"}]
        detect.apply_exceptions(result, exceptions, now=NOW)
        out = detect.deny_list(result)
        self.assertEqual(out["count"], 0)
        self.assertIn("ops", out["skipped"][0]["why"])

    def test_an_expired_exception_does_not_apply(self) -> None:
        result = {"sessions": {"8.8.4.4": {"level": "critical", "points": 10,
                                           "findings": [{"rule": "canary_used"}]}},
                  "evidence": {}}
        exceptions = [{"ip": "8.8.4.4", "until": int(NOW) - 1, "approver": "ops"}]
        detect.apply_exceptions(result, exceptions, now=NOW)
        self.assertEqual(detect.deny_list(result)["count"], 1)

    def test_an_incomplete_exception_is_rejected(self) -> None:
        import json
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "exceptions.json")
            json.dump({"exceptions": [{"ip": "8.8.4.4", "reason": "no expiry"},
                                      {"ip": "8.8.4.5", "until": int(NOW) + 60,
                                       "approver": "ops"}]}, open(path, "w"))
            loaded = detect.load_exceptions(path)
            self.assertEqual([item["ip"] for item in loaded], ["8.8.4.5"])
