"""Canary tokens: generated once, stored as hashes, matched from any text."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from tripwire import canary


class Generate(unittest.TestCase):
    def test_tokens_are_returned_once_and_only_hashes_stored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "canaries.json")
            res = canary.generate(3, "planted in /docs/api.md", path)
            self.assertEqual(res["count"], 3)
            self.assertEqual(len(set(res["tokens"])), 3)
            raw = open(path, encoding="utf-8").read()
            for token in res["tokens"]:
                self.assertNotIn(token, raw, "the token must never be written to disk")
            data = json.loads(raw)
            self.assertTrue(all(len(c["sha256"]) == 64 for c in data["canaries"]))

    def test_second_generation_appends(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "canaries.json")
            canary.generate(2, path=path)
            res = canary.generate(2, path=path)
            self.assertEqual(res["count"], 4)


class Match(unittest.TestCase):
    def test_a_planted_token_is_matched(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "canaries.json")
            token = canary.generate(1, path=path)["tokens"][0]
            registry = canary.load(path)
            hits = canary.match("Authorization: Bearer " + token, registry)
            self.assertEqual(len(hits), 1)

    def test_an_unplanted_token_is_not_matched(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "canaries.json")
            canary.generate(1, path=path)
            self.assertEqual(canary.match(canary.PREFIX + "made-up", canary.load(path)), [])

    def test_missing_registry_matches_nothing(self) -> None:
        self.assertEqual(canary.match("tw_abc", None), [])

    def test_revoked_canary_stops_matching(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "canaries.json")
            token = canary.generate(1, path=path)["tokens"][0]
            cid = canary.load(path)["canaries"][0]["id"]
            canary.revoke(cid, path)
            self.assertEqual(canary.match(token, canary.load(path)), [])

    def test_candidates_do_not_swallow_punctuation(self) -> None:
        text = "?key=tw_abc-123&next=1"
        self.assertEqual(canary.candidates(text), ["tw_abc-123"])


if __name__ == "__main__":
    unittest.main()


class Planting(unittest.TestCase):
    def test_tokens_are_written_into_decoy_documents(self) -> None:
        from tripwire import canary
        with tempfile.TemporaryDirectory() as td:
            registry = os.path.join(td, "canaries.json")
            www = os.path.join(td, "www")
            res = canary.generate(2, path=registry, plant_dir=www)
            self.assertEqual(len(res["planted"]), 2)
            names = sorted(os.listdir(www))
            self.assertEqual(names, ["api-1.md", "api-2.md"])
            text = open(os.path.join(www, names[0]), encoding="utf-8").read()
            self.assertIn(res["tokens"][0], text)
            self.assertEqual(len(canary.match(text, canary.load(registry))), 1)

    def test_the_registry_still_holds_only_hashes(self) -> None:
        from tripwire import canary
        with tempfile.TemporaryDirectory() as td:
            registry = os.path.join(td, "canaries.json")
            res = canary.generate(1, path=registry, plant_dir=os.path.join(td, "www"))
            self.assertNotIn(res["tokens"][0], open(registry, encoding="utf-8").read())
