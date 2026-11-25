"""The Jesta/OpenCode incident as a regression test, plus the two inbound rules."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest

from tripwire import canary, detect

NOW = 1795558000.0
DESKTOP = "Mozilla/5.0 (Macintosh) Chrome/157.0"
PHONE = "Mozilla/5.0 (Linux; Android 15; Pixel 10) Chrome/157.0 Mobile"
CURL = "curl/8.7.1"
IP = "81.2.3.4"


def row(ts, ua, path, status=200, method="GET", auth="none", referer="", ip=IP):
    return {"ts": ts, "ip": ip, "ua": ua, "method": method, "path": path,
            "status": status, "auth": auth, "referer": referer,
            "ua_platform": "mobile" if "Mobile" in ua else "desktop"}


def incident(auths=("key-A", "none", "made-up")) -> list[dict]:
    t = NOW - 400
    rows = [
        row(t, DESKTOP, "/", 403),
        row(t + 6, PHONE, "/", 403),
        row(t + 11, DESKTOP, "/api/openapi.json", 403),
        row(t + 16, DESKTOP, "/decoy/openapi.md", 200),
        row(t + 29, DESKTOP, "/api/v1/transactions", 200, referer="/decoy/openapi.md"),
        row(t + 40, CURL, "/api/v1/transactions", 401, auth=auths[0]),
        row(t + 42, CURL, "/api/v1/transactions", 401, auth=auths[1]),
        row(t + 44, CURL, "/api/v1/transactions", 401, auth=auths[2]),
        row(t + 60, CURL, "/api/v1/transactions/read", 405),
        row(t + 70, CURL, "/api/v1/transactions/read", 405),
    ]
    return rows


class Incident(unittest.TestCase):
    def test_the_incident_scores_high_on_the_base_rules(self) -> None:
        res = detect.analyse(incident(), now=NOW)
        session = res["sessions"][IP]
        rules = {f["rule"] for f in session["findings"]}
        self.assertEqual(session["level"], "high", session)
        self.assertTrue({"tool_switch", "ua_flip", "docs_link_follow",
                         "key_probing", "read_after_submit"} <= rules, rules)

    def test_spec_derived_novel_path_is_flagged(self) -> None:
        res = detect.analyse(incident(), now=NOW)
        paths = [p["path"] for p in res["spec_derived_paths"]]
        self.assertIn("/api/v1/transactions", paths)
        rules = {f["rule"] for f in res["sessions"][IP]["findings"]}
        self.assertIn("spec_derived_novel_path", rules)

    def test_a_canary_hit_is_critical_on_its_own(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "canaries.json")
            token = canary.generate(1, "planted in the decoy API doc", path)["tokens"][0]
            rows = [row(NOW - 30, DESKTOP, "/api/v1/accounts", 200, auth=token)]
            res = detect.analyse(rows, canary.load(path), now=NOW)
            session = res["sessions"][IP]
            self.assertEqual(session["level"], "critical")
            self.assertEqual(len(res["canary_hits"]), 1)
            self.assertIn("canary_used", {f["rule"] for f in session["findings"]})

    def test_a_benign_visitor_stays_low(self) -> None:
        rows = [row(NOW - 300 + i * 20, DESKTOP, "/pricing") for i in range(5)]
        self.assertEqual(detect.analyse(rows, now=NOW)["sessions"][IP]["level"], "low")

    def test_reading_a_spec_then_a_known_page_is_not_novel(self) -> None:
        t = NOW - 100
        rows = [row(t, DESKTOP, "/pricing"),
                row(t + 5, DESKTOP, "/docs/api.md"),
                row(t + 10, DESKTOP, "/pricing")]
        # "/pricing" was seen before the document, so it is not spec-derived
        self.assertEqual([p["path"] for p in detect.spec_derived_paths(rows)], [])


class Ledger(unittest.TestCase):
    def _write(self, rows: list[dict]) -> str:
        td = tempfile.mkdtemp()
        log = os.path.join(td, "access.jsonl")
        with open(log, "w", encoding="utf-8") as fh:
            for r in rows:
                item = dict(r)
                item["ts"] = time.time() - 60          # inside the default window
                fh.write(json.dumps(item) + "\n")
        return log

    def test_an_alert_goes_into_the_mandate_chain(self) -> None:
        td = tempfile.mkdtemp()
        ledger = os.path.join(td, "alerts.jsonl")
        res = detect.watch(self._write(incident()), ledger=ledger)
        self.assertEqual(res["flagged"], 1)
        body = json.loads(open(ledger, encoding="utf-8").read().strip().splitlines()[-1])["body"]
        self.assertEqual((body["type"], body["action"]), ("control", "alert"))

    def test_a_quiet_log_writes_nothing(self) -> None:
        td = tempfile.mkdtemp()
        ledger = os.path.join(td, "alerts.jsonl")
        rows = [row(time.time() - 30 + i, DESKTOP, "/pricing") for i in range(4)]
        detect.watch(self._write(rows), ledger=ledger)
        self.assertFalse(os.path.exists(ledger))


if __name__ == "__main__":
    unittest.main()
