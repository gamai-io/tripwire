"""A source-rotating flood must be refused, not half-scored and called clean."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest

from tripwire import cli, detect

BASE = 1_795_560_000.0


def write(path, count):
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(count):
            fh.write(json.dumps({"ts": BASE + i, "ip": "198.51.100.%d" % i,
                                 "ua": "curl/8.7.1", "method": "GET",
                                 "path": "/x", "status": 200, "auth": "k"}) + "\n")


class SourceCap(unittest.TestCase):
    def test_the_stream_refuses_instead_of_dropping_sources(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            ledger = os.path.join(td, "l.jsonl")
            write(log, 30)
            out = detect.watch_stream(log, window=10 ** 9, chunk=10,
                                      max_sources=10, ledger=ledger)
            self.assertIn("too many distinct sources", out.get("error", ""))
            self.assertEqual(out["sources"], 10)
            self.assertFalse(os.path.exists(ledger),
                             "a refused run wrote to the evidence ledger")

    def test_the_batch_path_refuses_too(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            write(log, 30)
            out = detect.watch(log, window=10 ** 9, now=BASE + 31, max_sources=10)
            self.assertIn("too many distinct sources", out.get("error", ""))

    def test_a_normal_run_is_unaffected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            write(log, 5)
            out = detect.watch(log, window=10 ** 9, now=BASE + 6, max_sources=10)
            self.assertNotIn("error", out)
            self.assertEqual(len(out["sessions"]), 5)

    def test_the_cli_exits_three(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "a.jsonl")
            write(log, 30)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.main(["watch", "--log", log, "--window", "1000000000",
                                 "--max-sources", "10"])
            self.assertEqual(code, 3, out.getvalue())
            self.assertEqual(json.loads(out.getvalue())["error"], "TooManySources")


if __name__ == "__main__":
    unittest.main()
