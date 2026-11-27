"""State, baseline and canary files are read back into decisions; refuse ambiguity."""
from __future__ import annotations

import os
import pathlib
import tempfile
import unittest

from tripwire import baseline, canary, strictjson


class StrictState(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name

    def tearDown(self):
        self.td.cleanup()

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        pathlib.Path(path).write_text(text, encoding="utf-8")
        return path

    def test_duplicate_key_state_falls_back_to_empty(self):
        path = self.write("baseline.json", '{"version": 1, "paths": {}, "paths": {"a": 1}}')
        self.assertEqual(baseline.load(path)["paths"], {})

    def test_big_integer_state_is_refused(self):
        path = self.write("baseline.json", '{"version": 1, "paths": {}, "samples": 12345678901234567890}')
        self.assertEqual(baseline.load(path)["samples"], 0)

    def test_a_normal_baseline_still_loads(self):
        path = self.write("baseline.json", '{"version": 1, "paths": {"/x": {"n": 1}}, "samples": 1}')
        self.assertEqual(baseline.load(path)["samples"], 1)

    def test_canary_duplicate_key_is_refused(self):
        path = self.write("canaries.json", '{"version": 1, "canaries": [], "canaries": ["x"]}')
        with self.assertRaises(canary.RegistryError):
            canary.load(path, strict=True)

    def test_canary_nan_is_refused(self):
        path = self.write("canaries.json", '{"version": 1, "canaries": [NaN]}')
        with self.assertRaises(canary.RegistryError):
            canary.load(path, strict=True)

    def test_the_module_rejects_and_accepts(self):
        with self.assertRaises(strictjson.StrictJSONError):
            strictjson.loads_strict('{"a": 1, "a": 2}')
        self.assertEqual(strictjson.loads_strict('{"a": 1}'), {"a": 1})


if __name__ == "__main__":
    unittest.main()
