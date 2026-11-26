"""Low/medium fixes from the adversarial review: L1, L2, L3 and L5.

Each test is written against the failure the reviewer demonstrated, not against
the implementation: a spoofed crawler UA, a 2 MiB line, duplicate JSON keys, an
impossible timestamp, and a trusted-proxy prefix that trusts the attacker.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import time
import unittest

from tripwire import cli, detect, logread

BASE = 1_795_560_000.0
BOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
CURL = "curl/8.7.1"


def row(ts, ip, path, status=200, ua=CURL):
    return {"ts": ts, "ip": ip, "ua": ua, "method": "GET", "path": path,
            "status": status, "auth": "none"}


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(list(argv))
    text = out.getvalue()
    try:
        payload = json.loads(text) if text.strip() else {}
    except ValueError:
        payload = {}
    return code, payload, text


def write_jsonl(path, items):
    with open(path, "w", encoding="utf-8") as fh:
        for item in items:
            fh.write(json.dumps(item) + "\n")


class SpoofedGoodBot(unittest.TestCase):
    """L1: `curl -A Googlebot` must not inherit the crawler exemption."""

    def _walk(self, statuses):
        now = BASE + 100
        items = [row(now + i, "198.51.100.7", "/walk/%02d" % i, statuses[i], BOT)
                 for i in range(60)]
        return detect.analyse(items, window=600, now=now + 61)

    def test_a_bot_ua_with_failed_auth_is_flagged_by_path_burst(self) -> None:
        statuses = [401 if i in (0, 7, 19, 33, 51) else 200 for i in range(60)]
        session = self._walk(statuses)["sessions"]["198.51.100.7"]
        rules = {finding["rule"] for finding in session["findings"]}
        self.assertIn("path_burst", rules,
                      "a 401-collecting 'Googlebot' kept the crawler exemption")
        self.assertNotEqual(session["level"], "low")

    def test_a_real_crawler_walking_clean_paths_stays_exempt(self) -> None:
        session = self._walk([200] * 60)["sessions"]["198.51.100.7"]
        rules = {finding["rule"] for finding in session["findings"]}
        self.assertNotIn("path_burst", rules)
        self.assertEqual(session["level"], "low")


class OversizeLines(unittest.TestCase):
    """L2: one absurd line must not cost its whole length in RSS."""

    def _path(self, td):
        path = os.path.join(td, "a.jsonl")
        good = [row(BASE, "8.8.4.4", "/one"), row(BASE + 1, "8.8.4.4", "/two")]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(good[0]) + "\n")
            fh.write("x" * (2 * 1024 * 1024) + "\n")
            fh.write(json.dumps(good[1]) + "\n")
        return path

    def test_a_two_mib_line_is_skipped_and_the_good_lines_are_analysed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._path(td)
            rows, stats = logread.load_stats(path)
            self.assertEqual([item["path"] for item in rows], ["/one", "/two"])
            self.assertEqual(stats["oversize"], 1)
            self.assertEqual(stats["skipped"], 1)

            result = detect.watch(path, window=10 ** 9)
            self.assertEqual(result["rows"], 2)
            self.assertEqual(result["oversize_lines"], 1)
            self.assertEqual(result["skipped_lines"], 1)
            self.assertEqual(result["sessions"]["8.8.4.4"]["level"], "low")

    def test_the_streaming_reader_counts_it_too(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._path(td)
            result = detect.watch_stream(path, window=10 ** 9, chunk=10)
            self.assertEqual(result["rows"], 2)
            self.assertEqual(result["oversize_lines"], 1)
            self.assertEqual(result["skipped_lines"], 1)


class JsonlHardening(unittest.TestCase):
    """L3: duplicate keys and impossible timestamps are skipped and counted."""

    def test_a_duplicate_key_is_skipped_not_last_wins(self) -> None:
        now = time.time() - 60
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(row(now, "8.8.4.4", "/good")) + "\n")
                fh.write(json.dumps({"ts": now, "ip": "198.51.100.9",
                                     "path": "/first"})[:-1]
                         + ', "ip": "203.0.113.9", "status": 200}\n')
            rows, stats = logread.load_stats(path)
            self.assertEqual([item["ip"] for item in rows], ["8.8.4.4"],
                             "the duplicate-key row was accepted (last wins)")
            self.assertEqual(stats["duplicate_keys"], 1)
            self.assertEqual(stats["skipped"], 1)

            result = detect.watch(path, window=600)
            self.assertEqual(result["rows"], 1)
            self.assertEqual(result["duplicate_keys"], 1)
            self.assertEqual(result["skipped_lines"], 1)

    def test_an_impossible_epoch_is_skipped_and_counted(self) -> None:
        now = time.time()
        future = now + 20 * 365 * 86_400          # beyond now + 10 years
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.jsonl")
            write_jsonl(path, [row(now, "8.8.4.4", "/ok"),
                               row(future, "198.51.100.9", "/future"),
                               row(946_684_799, "198.51.100.10", "/ancient")])
            rows, stats = logread.load_stats(path)
            self.assertEqual([item["path"] for item in rows], ["/ok"])
            self.assertEqual(stats["bad_timestamps"], 2)
            self.assertEqual(stats["skipped"], 2)

            result = detect.watch(path, window=600)
            self.assertEqual(result["rows"], 1)
            self.assertEqual(result["bad_timestamps"], 2)
            self.assertEqual(result["skipped_lines"], 2)

    def test_hour_99_is_not_normalised_into_a_valid_time(self) -> None:
        template = ('203.0.113.9 - - [%s] "GET /x HTTP/1.1" 200 1 "-" '
                    '"curl/8.7.1"')
        for stamp in ("25/Nov/2026:99:00:22 +0100",
                      "25/Nov/2026:00:99:22 +0100",
                      "25/Nov/2026:00:00:99 +0100"):
            with self.subTest(stamp=stamp):
                self.assertIsNone(logread.parse_combined(template % stamp),
                                  "calendar.timegm silently rolled %r forward" % stamp)

    def test_a_combined_log_with_hour_99_counts_as_skipped(self) -> None:
        good = ('203.0.113.9 - - [25/Nov/2026:00:00:22 +0100] '
                '"GET /docs/api.md HTTP/1.1" 200 1 "-" "curl/8.7.1"')
        bad = good.replace("00:00:22", "99:00:22")
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "access.log")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(good + "\n")
                fh.write(bad + "\n")
            rows, stats = logread.load_stats(path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(stats["skipped"], 1)


class TrustedProxyWidth(unittest.TestCase):
    """L5: a /8 in --trusted-proxy trusts the attacker's X-Forwarded-For."""

    def _log(self, td):
        path = os.path.join(td, "a.jsonl")
        write_jsonl(path, [row(time.time() - 30, "8.8.4.4", "/pricing",
                               ua="Mozilla/5.0 (Macintosh) Chrome/157")])
        return path

    def test_a_wide_ipv4_prefix_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            code, out, text = run_cli("watch", "--log", self._log(td),
                                      "--trusted-proxy", "10.0.0.1/8")
            self.assertEqual(code, 2, text)
            self.assertEqual(out.get("error"), "Usage")
            self.assertIn("allow-wide-proxy", out.get("message", ""))

    def test_a_wide_ipv6_prefix_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            code, out, _ = run_cli("watch", "--log", self._log(td),
                                   "--trusted-proxy", "fd00::/32")
            self.assertEqual(code, 2)
            self.assertEqual(out.get("error"), "Usage")

    def test_a_narrow_prefix_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            code, out, text = run_cli("watch", "--log", self._log(td),
                                      "--trusted-proxy", "10.0.0.0/24")
            self.assertEqual(code, 0, text)

    def test_a_wide_prefix_is_accepted_with_the_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            code, out, text = run_cli("watch", "--log", self._log(td),
                                      "--trusted-proxy", "10.0.0.0/8",
                                      "--allow-wide-proxy")
            self.assertEqual(code, 0, text)

    def test_a_garbage_cidr_is_a_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            code, out, _ = run_cli("watch", "--log", self._log(td),
                                   "--trusted-proxy", "not-a-network")
            self.assertEqual(code, 2)
            self.assertEqual(out.get("error"), "Usage")


class StateTtlIsWired(unittest.TestCase):
    """L5: --state-ttl must decide when the same alert is new again."""

    def test_state_ttl_decides_when_an_alert_is_new_again(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            state = os.path.join(td, "state.json")
            base = time.time() - 120
            write_jsonl(log, [row(base + i, "8.8.4.4", "/api/v1/login", 401)
                              for i in range(6)])
            now = int(time.time())
            first, out1, _ = run_cli("watch", "--log", log, "--state", state,
                                     "--state-ttl", "60", "--now", str(now))
            self.assertEqual(out1.get("new_alerts"), 1, out1)
            second, out2, _ = run_cli("watch", "--log", log, "--state", state,
                                      "--state-ttl", "60", "--now", str(now + 30))
            self.assertEqual(out2.get("new_alerts"), 0, out2)
            third, out3, _ = run_cli("watch", "--log", log, "--state", state,
                                     "--state-ttl", "60", "--now", str(now + 120))
            self.assertEqual(out3.get("new_alerts"), 1,
                             "a 60s --state-ttl did not expire the alert")


if __name__ == "__main__":
    unittest.main()
