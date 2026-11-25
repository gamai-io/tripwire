"""The evasion that beats every per-address rule: one key, many addresses."""
from __future__ import annotations

import unittest

from tripwire import detect

NOW = 1795558000.0
CURL = "curl/8.7.1"


def row(ip, ts, status=401, auth="stolen", path="/api/v1/x", ua=CURL):
    return {"ts": ts, "ip": ip, "ua": ua, "method": "GET", "path": path,
            "status": status, "auth": auth, "referer": "",
            "ua_platform": "desktop"}


def rotating(addresses=8, each=5, status=401, auth="stolen"):
    rows = []
    for i in range(addresses):
        for j in range(each):
            rows.append(row("198.51.100.%d" % (10 + i), NOW - 100 + i * each + j,
                            status=status, auth=auth))
    return rows


class Cluster(unittest.TestCase):
    def test_a_key_rotated_across_addresses_is_detected(self) -> None:
        rows = rotating()
        clusters = detect.key_across_addresses(rows)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(len(clusters[0]["addresses"]), 8)
        res = detect.analyse(rows, now=NOW)
        session = res["sessions"]["198.51.100.10"]
        self.assertIn("key_across_addresses", {f["rule"] for f in session["findings"]})
        self.assertEqual(session["level"], "high")

    def test_a_shared_working_key_is_normal_infrastructure(self) -> None:
        rows = rotating(addresses=4, each=10, status=200, auth="service-key")
        self.assertEqual(detect.key_across_addresses(rows), [])
        self.assertEqual(detect.analyse(rows, now=NOW)["flagged"], 0)

    def test_a_single_address_is_not_a_cluster(self) -> None:
        rows = [row("198.51.100.10", NOW - 60 + i) for i in range(20)]
        self.assertEqual(detect.key_across_addresses(rows), [])

    def test_anonymous_requests_are_ignored(self) -> None:
        rows = rotating(auth="none")
        self.assertEqual(detect.key_across_addresses(rows), [])

    def test_a_few_failures_on_three_addresses_stay_below_the_bar(self) -> None:
        rows = rotating(addresses=3, each=1)          # 3 addresses, 3 failures
        self.assertEqual(detect.key_across_addresses(rows), [])

    def test_the_cluster_is_deniable_evidence(self) -> None:
        res = detect.analyse(rotating(), now=NOW)
        entry = res["sessions"]["198.51.100.10"]
        ok, why = detect.deny_evidence(entry, res["evidence"]["198.51.100.10"])
        self.assertTrue(ok, why)


if __name__ == "__main__":
    unittest.main()
