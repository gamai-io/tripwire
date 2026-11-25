#!/usr/bin/env python3
"""Replay the reported intrusion and show, request by request, what the detector saw.

    python3 tools/replay.py            # timeline + verdict
    python3 tools/replay.py --json     # the same as data

Times are relative to the first request (04:24:57 in the report). The sequence is
the one summarised from the Jesta incident: refused front page, a fake phone
user-agent six seconds later, the API definition refused, a decoy document
served, a link from that document followed, three credential guesses inside four
seconds, then two reads of a submit-only endpoint.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tripwire import detect  # noqa: E402

DESKTOP = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/157.0.0.0"
PHONE = "Mozilla/5.0 (Linux; Android 15; Pixel 10) Chrome/157.0.0.0 Mobile"
CURL = "curl/8.7.1"
T0 = 1_795_558_000.0
IP = "81.2.3.4"


def row(offset, ua, path, status=200, method="GET", auth="none", referer=""):
    return {"ts": T0 + offset, "ip": IP, "ua": ua, "method": method, "path": path,
            "status": status, "auth": auth, "referer": referer,
            "ua_platform": "mobile" if "Mobile" in ua else "desktop"}


def timeline() -> list[dict]:
    return [
        row(0, DESKTOP, "/", 403),
        row(6, PHONE, "/", 403),
        row(11, DESKTOP, "/api/openapi.json", 403),
        row(16, DESKTOP, "/decoy/openapi.md"),
        row(29, DESKTOP, "/api/v1/transactions", referer="/decoy/openapi.md"),
        row(40, CURL, "/api/v1/transactions", 401, auth="key-A"),
        row(42, CURL, "/api/v1/transactions", 401, auth="none"),
        row(44, CURL, "/api/v1/transactions", 401, auth="made-up"),
        row(60, CURL, "/api/v1/transactions/read", 405),
        row(70, CURL, "/api/v1/transactions/read", 405),
    ]


def build(rows: list[dict]) -> list[dict]:
    """Score the log as it grew, so each line shows what was known by then."""
    out = []
    for index in range(1, len(rows) + 1):
        seen = rows[:index]
        result = detect.analyse(seen, now=seen[-1]["ts"] + 0.01, window=10 ** 9)
        session = result["sessions"].get(IP) or {"points": 0, "level": "low",
                                                 "findings": []}
        out.append({
            "offset_s": int(rows[index - 1]["ts"] - T0),
            "request": "%s %s" % (rows[index - 1]["method"], rows[index - 1]["path"]),
            "status": rows[index - 1]["status"],
            "points": session["points"],
            "level": session["level"],
            "new_rules": sorted({f["rule"] for f in session["findings"]
                                 if not f.get("suppressed")}),
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    steps = build(timeline())
    final = steps[-1]
    if args.json:
        print(json.dumps({"steps": steps, "final": final}, indent=1, sort_keys=True))
        return 0
    print("%6s  %-42s %5s %6s  %s" % ("t+", "request", "code", "points", "level"))
    for step in steps:
        print("%5ds  %-42s %5d %6d  %-8s %s"
              % (step["offset_s"], step["request"], step["status"], step["points"],
                 step["level"], ",".join(step["new_rules"])))
    first_high = next((s for s in steps if s["level"] in ("high", "critical")), None)
    print("\nverdict: %s, %d points at the last request" % (final["level"].upper(),
                                                            final["points"]))
    if first_high:
        print("first high: t+%ds (%s) — this is a replay of the reported sequence, "
              "scored after the fact, not a live block" % (first_high["offset_s"],
                                                           first_high["request"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
