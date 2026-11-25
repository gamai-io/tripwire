#!/usr/bin/env python3
"""Measure parse + analyse on synthetic logs, including one very noisy address."""
from __future__ import annotations

import json
import os
import random
import resource
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tripwire import detect, logread  # noqa: E402

UA = "curl/8.7.1"


def write_log(path, n, ips=50, paths=200):
    rng = random.Random(7)
    base = 1_795_000_000.0
    with open(path, "w") as fh:
        for i in range(n):
            fh.write(json.dumps({
                "ts": base + i * 0.1, "ip": "8.8.%d.%d" % (i % ips, i % 251),
                "ua": UA, "method": "GET", "path": "/p/%d" % (i % paths),
                "status": 200 if i % 5 else 401, "auth": "k"}) + "\n")


def one_run(n, **kwargs):
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "a.jsonl")
        write_log(path, n, **kwargs)
        start = time.perf_counter()
        rows = logread.load(path)
        parsed = time.perf_counter() - start
        start = time.perf_counter()
        res = detect.analyse(rows, now=max(r["ts"] for r in rows) + 1, window=86400)
        analysed = time.perf_counter() - start
        return {"lines": n, "parse_s": round(parsed, 2), "analyse_s": round(analysed, 2),
                "sources": res["sources"],
                "rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)}


def main():
    out = []
    for n in (1000, 5000, 20000):
        out.append(one_run(n))
        print(json.dumps(out[-1]))
    print("single address, 20000 lines on 200 paths:")
    print(json.dumps(one_run(20000, ips=1)))


if __name__ == "__main__":
    main()
