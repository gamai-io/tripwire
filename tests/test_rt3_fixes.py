"""Regressions for the third adversarial review (RT3).

The important lesson from RT3: the library was tested, the *shipped CLI* was
not. Most of these tests therefore drive `cli.main` exactly as a user does.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import time
import unittest

from tripwire import canary, cli, detect

BASE = 1_795_560_000.0


def row(ip, ts, path="/api/v1/invoices", status=200, ua="curl/8.7.1"):
    return {"ts": ts, "ip": ip, "ua": ua, "method": "GET", "path": path,
            "status": status, "auth": "k"}


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for item in rows:
            fh.write(json.dumps(item) + "\n")


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


def medium_log(path, now=None):
    now = time.time() - 30 if now is None else now
    write_jsonl(path, [
        row("8.8.4.4", now, "/", 200, "Mozilla/5.0 (Macintosh) Chrome/157"),
        row("8.8.4.4", now + 1, "/", 200,
            "Mozilla/5.0 (Linux; Android 15) Mobile"),
        row("8.8.4.4", now + 2, "/api", 200),
    ])


def identity_log(path, now=None):
    """6 rejected logins: identity evidence, so the address is blockable."""
    now = time.time() - 30 if now is None else now
    write_jsonl(path, [row("8.8.4.4", now + i, "/api/v1/login", 401)
                       for i in range(6)])


class CliForwardsItsFlags(unittest.TestCase):
    def test_min_level_filters_what_lands_in_the_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            ledger = os.path.join(td, "led")
            state = os.path.join(td, "st")
            medium_log(log)
            code, out, _ = run_cli("watch", "--log", log, "--min-level", "high",
                                   "--ledger", ledger, "--state", state)
            self.assertEqual(code, 0, out)
            self.assertFalse(os.path.exists(ledger),
                             "a medium alert was written at --min-level high")
            self.assertTrue(os.path.exists(state), "--state was not created")

    def test_state_stops_the_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            ledger = os.path.join(td, "led")
            state = os.path.join(td, "st")
            identity_log(log)
            first, out1, _ = run_cli("watch", "--log", log, "--ledger", ledger,
                                     "--state", state)
            self.assertEqual(first, 1, out1)
            self.assertEqual(len(open(ledger).readlines()), 1)
            second, out2, _ = run_cli("watch", "--log", log, "--ledger", ledger,
                                      "--state", state)
            self.assertEqual(out2["new_alerts"], 0)
            self.assertEqual(len(open(ledger).readlines()), 1,
                             "the repeat wrote another ledger line")

    def test_an_exception_lifts_an_existing_block(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            deny = os.path.join(td, "deny.conf")
            exceptions = os.path.join(td, "exc.json")
            identity_log(log)
            run_cli("watch", "--log", log, "--deny-map", deny)
            self.assertIn("deny 8.8.4.4;", open(deny).read())
            json.dump({"exceptions": [{"ip": "8.8.4.4",
                                       "until": int(time.time()) + 3600,
                                       "approver": "ops", "reason": "ours"}]},
                      open(exceptions, "w"))
            code, out, _ = run_cli("watch", "--log", log, "--deny-map", deny,
                                   "--exceptions", exceptions)
            self.assertNotIn("deny 8.8.4.4;", open(deny).read(),
                             "an active exception did not lift the block")

    def test_reload_runs_only_when_the_list_changes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            deny = os.path.join(td, "deny.conf")
            marker = os.path.join(td, "reloads")
            identity_log(log)
            cmd = "echo x >> %s" % marker
            run_cli("watch", "--log", log, "--deny-map", deny, "--reload-cmd", cmd)
            run_cli("watch", "--log", log, "--deny-map", deny, "--reload-cmd", cmd)
            self.assertEqual(open(marker).read().count("x"), 1,
                             "nginx was reloaded for an unchanged list")


class CliRefusals(unittest.TestCase):
    def test_deny_cap_is_a_refusal_not_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            identity_log(log)
            code, out, text = run_cli("watch", "--log", log, "--deny-map",
                                      os.path.join(td, "deny.conf"),
                                      "--deny-max", "0")
            self.assertEqual(code, 4, text)
            self.assertEqual(out.get("error"), "DenyRefused")

    def test_an_unwritable_deny_path_is_a_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            blocker = os.path.join(td, "afile")
            open(blocker, "w").write("x")
            identity_log(log)
            code, out, text = run_cli("watch", "--log", log, "--deny-map",
                                      os.path.join(blocker, "deny.conf"))
            self.assertEqual(code, 4, text)
            self.assertEqual(out.get("error"), "DenyRefused")

    def test_a_missing_explicit_registry_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            medium_log(log)
            code, out, _ = run_cli("watch", "--log", log, "--registry",
                                   os.path.join(td, "nope.json"))
            self.assertEqual(code, 4)
            self.assertEqual(out.get("error"), "RegistryMissing")

    def test_a_corrupt_registry_is_never_erased_by_revoke(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "canaries.json")
            open(path, "w").write("{not json")
            with self.assertRaises(canary.RegistryError):
                canary.revoke("abc123", path)
            self.assertEqual(open(path).read(), "{not json")


class PathAnomalies(unittest.TestCase):
    def _warm(self, log, baseline, state, ledger, windows=4):
        for i in range(windows):
            write_jsonl(log, [row("198.51.100.%d" % (n % 250),
                                  BASE - 100 + i * 10 + n * 0.1,
                                  status=200) for n in range(5) for _ in range(4)])
            detect.watch(log, window=10 ** 9, baseline_path=baseline,
                         baseline_floor=10, state_path=state, ledger=ledger)

    def test_state_suppresses_a_repeated_anomaly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            baseline = os.path.join(td, "b.json")
            state = os.path.join(td, "s.json")
            ledger = os.path.join(td, "l.jsonl")
            self._warm(log, baseline, state, ledger)
            write_jsonl(log, [row("198.51.100.%d" % (n % 250), BASE + n * 0.1,
                                  status=404) for n in range(70) for _ in range(2)])
            first = detect.watch(log, window=10 ** 9, baseline_path=baseline,
                                 baseline_floor=10, state_path=state, ledger=ledger)
            self.assertEqual(len(first["new_path_anomalies"]), 1)
            second = detect.watch(log, window=10 ** 9, baseline_path=baseline,
                                  baseline_floor=10, state_path=state, ledger=ledger)
            self.assertEqual(second["new_path_anomalies"], [])
            kinds = [json.loads(line)["body"].get("kind")
                     for line in open(ledger)]
            self.assertEqual(kinds.count("path_anomaly"), 1)

    def test_sources_on_an_exception_do_not_raise_an_anomaly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            baseline = os.path.join(td, "b.json")
            self._warm(log, baseline, "", "")
            rows = [row("198.51.100.%d" % n, BASE + n * 0.1, status=404)
                    for n in range(20) for _ in range(2)]
            write_jsonl(log, rows)
            exceptions = [{"ip": "198.51.100.%d" % n,
                           "until": BASE + 10 ** 6, "approver": "ops",
                           "reason": "our scanner"} for n in range(20)]
            out = detect.watch(log, window=10 ** 9, baseline_path=baseline,
                               baseline_floor=10, exceptions=exceptions,
                               now=BASE + 100)
            self.assertEqual(out["path_anomalies"], [])


class WindowsAndTypes(unittest.TestCase):
    def test_a_stale_auth_failure_does_not_corroborate(self) -> None:
        now = BASE + 10_000
        rows = [row("8.8.4.4", now - 1_000, "/api/v1/login", 401),
                row("8.8.4.4", now, "/docs/api", 200),
                row("8.8.4.4", now + 1, "/api/v1/x%d" % 1, 200)]
        out = detect.analyse(rows, window=60, now=now)
        session = out["sessions"]["8.8.4.4"]
        self.assertNotEqual(session["level"], "high", session)

    def test_a_future_row_does_not_blind_the_stream(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            now = time.time() - 400
            rows = [row("198.51.100.9", now + i, "/app") for i in range(300)]
            rows.insert(100, row("203.0.113.7", now + 5000, "/future"))
            write_jsonl(log, rows)
            out = detect.watch_stream(log, window=10 ** 9, chunk=50)
            self.assertEqual(out["future_rows"], 1)
            self.assertGreater(out["rows_in_window"], 0)

    def test_an_all_future_log_is_could_not_analyse(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            write_jsonl(log, [row("8.8.4.4", time.time() + 5000 + i)
                              for i in range(5)])
            code, out, _ = run_cli("watch", "--log", log)
            self.assertEqual(code, 3, out)
            self.assertEqual(out.get("error"), "no rows in window")

    def test_bad_field_types_do_not_crash(self) -> None:
        now = time.time() - 30
        rows = [row("8.8.4.4", now), {"ts": "not-a-number", "ip": "8.8.4.4"},
                {"ts": now + 1, "ip": "8.8.4.4", "status": "abc"}]
        out = detect.analyse(rows, now=now + 2)
        self.assertEqual(out["invalid_rows"], 1)
        self.assertIn("8.8.4.4", out["sessions"])


class DenyFileIsUntrusted(unittest.TestCase):
    def test_a_previous_private_ip_is_dropped(self) -> None:
        result = {"sessions": {"10.1.2.3": {"level": "high", "points": 9,
                                            "findings": [{"rule": "canary_used"}]}},
                  "evidence": {}}
        previous = {"10.1.2.3": {"ip": "10.1.2.3", "level": "high", "points": 9,
                                 "expires": int(time.time()) + 3600,
                                 "rules": ["canary_used"], "reason": "x"}}
        out = detect.deny_list(result, previous=previous)
        self.assertEqual(out["count"], 0, "a private address survived the merge")

    def test_a_json_entry_cannot_inject_nginx(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            deny = os.path.join(td, "deny.conf")
            evil = os.path.join(td, "deny.json")
            json.dump({"deny": [{"ip": "1.2.3.4;\nallow all", "level": "high",
                                 "points": 9, "expires": int(time.time()) + 3600,
                                 "rules": ["x"], "reason": "x"}]}, open(evil, "w"))
            result = {"sessions": {}, "evidence": {}}
            detect.write_deny_files(result, deny, evil)
            text = open(deny).read()
            self.assertNotIn("allow all", text)
            self.assertNotIn("deny 1.2.3.4;", text)


class Packaging(unittest.TestCase):
    def test_the_watch_unit_cannot_write_nginx(self) -> None:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        unit = open(os.path.join(here, "packaging", "tripwire-watch.service"),
                    encoding="utf-8").read()
        self.assertNotIn("/etc/nginx", unit,
                         "the unprivileged unit cannot write /etc/nginx")
        self.assertIn("/var/lib/tripwire/deny.conf", unit)
        self.assertIn("SupplementaryGroups=adm", unit)
        self.assertIn("--state", unit)
        self.assertIn("--min-level", unit)

    def test_the_apply_script_tests_and_rolls_back(self) -> None:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(here, "packaging", "tripwire-apply-nginx.sh")
        import subprocess
        subprocess.run(["sh", "-n", path], check=True)
        text = open(path, encoding="utf-8").read()
        self.assertIn("-t", text)
        self.assertIn("previous file restored", text)

    def test_the_sdist_ships_what_the_docs_tell_people_to_run(self) -> None:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manifest = open(os.path.join(here, "MANIFEST.in"), encoding="utf-8").read()
        for needed in ("packaging", "tools", "CLAIMS.md", "CHANGELOG.md",
                       "SECURITY.md"):
            self.assertIn(needed, manifest)


if __name__ == "__main__":
    unittest.main()
