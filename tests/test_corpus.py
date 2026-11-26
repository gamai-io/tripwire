"""A real nginx log, redacted, frozen as a regression corpus.

The corpus keeps timestamps (shifted), statuses, sizes and the *number* of distinct
paths/sources/UA classes; addresses, paths, queries and user agents are replaced.
`tools/redact_corpus.py` regenerates it from a local log.
"""
from __future__ import annotations

import json
import os
import re
import unittest

from tripwire import detect

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus", "redacted")
LOG = os.path.join(CORPUS, "access.log")
MANIFEST = os.path.join(CORPUS, "manifest.json")


class Corpus(unittest.TestCase):
    def test_the_corpus_has_no_original_addresses_or_services(self):
        text = open(LOG, encoding="utf-8").read()
        self.assertNotIn("ipify", text)
        self.assertNotIn("/api/", text)
        self.assertNotIn("/wp-", text)
        self.assertNotIn("/.env", text)
        for address in re.findall(r"^(\S+) ", text, re.M):
            self.assertTrue(
                address.startswith(("203.0.113.", "198.51.100.", "10.0.0.")),
                "non-documentation address survived redaction: %s" % address)

    def test_the_manifest_matches_the_file(self):
        manifest = json.load(open(MANIFEST, encoding="utf-8"))
        lines = sum(1 for _ in open(LOG, encoding="utf-8"))
        self.assertEqual(manifest["lines"], lines)
        self.assertEqual(manifest["lines"], 2000)

    def test_detection_on_the_corpus_is_frozen(self):
        out = detect.watch(LOG, window=86400, fmt="combined",
                           min_level="medium")
        self.assertEqual(out["rows"], 2000)
        self.assertEqual(out["sources"], 201)
        self.assertEqual(out["flagged"], 2)
        levels = {}
        rules = {}
        for session in out["sessions"].values():
            levels[session["level"]] = levels.get(session["level"], 0) + 1
            for finding in session["findings"]:
                rules[finding["rule"]] = rules.get(finding["rule"], 0) + 1
        self.assertEqual(levels, {"low": 199, "high": 1, "medium": 1})
        self.assertEqual(rules.get("velocity"), 2)
        self.assertEqual(rules.get("path_burst"), 2)


if __name__ == "__main__":
    unittest.main()
