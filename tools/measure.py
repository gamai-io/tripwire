#!/usr/bin/env python3
"""Measure the detector on a labelled corpus: false positives, misses, rules.

    python3 tools/measure.py --corpus corpus
    python3 tools/measure.py --corpus corpus --json out/measure.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tripwire import detect, logread  # noqa: E402

LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def run_session(rows: list[dict], registry: dict) -> dict:
    now = max(float(r.get("ts") or 0) for r in rows) + 1
    res = detect.analyse(rows, registry, window=10 ** 9, now=now)
    session = res["sessions"].get(str(rows[0].get("ip"))) or {
        "level": "low", "points": 0, "findings": []}
    return {"level": session["level"], "points": session["points"],
            "rules": sorted({f["rule"] for f in session["findings"]
                             if not f.get("suppressed")}),
            "suppressed": sorted({f["rule"] for f in session["findings"]
                                  if f.get("suppressed")}),
            "canary": bool(res["canary_hits"])}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus")
    ap.add_argument("--json", default=None)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    manifest = json.load(open(os.path.join(args.corpus, "manifest.json"),
                              encoding="utf-8"))
    registry = {"version": 1, "canaries": []}

    results = []
    for item in manifest["sessions"]:
        rows = logread.load(item["file"], "jsonl")
        if not rows:
            continue
        outcome = run_session(rows, registry)
        outcome.update({"label": item["label"], "kind": item["kind"],
                        "file": item["file"]})
        results.append(outcome)

    benign = [r for r in results if r["label"] == "benign"]
    attack = [r for r in results if r["label"] == "attack"]

    def share(rows, level):
        return sum(1 for r in rows if r["level"] == level)

    fp_high = sum(1 for r in benign if LEVELS[r["level"]] >= 2)
    fp_any = sum(1 for r in benign if LEVELS[r["level"]] >= 1)
    tp_high = sum(1 for r in attack if LEVELS[r["level"]] >= 2)
    tp_any = sum(1 for r in attack if LEVELS[r["level"]] >= 1)

    summary = {
        "benign_sessions": len(benign),
        "benign_high_or_critical": fp_high,
        "benign_medium_or_higher": fp_any,
        "benign_fp_rate_high": round(fp_high / max(len(benign), 1), 4),
        "benign_fp_rate_any": round(fp_any / max(len(benign), 1), 4),
        "attack_sessions": len(attack),
        "attack_detected_high": tp_high,
        "attack_detected_any": tp_any,
        "attack_recall_high": round(tp_high / max(len(attack), 1), 4),
        "attack_recall_any": round(tp_any / max(len(attack), 1), 4),
        "benign_by_kind": _by_kind(benign, "kind"),
        "attack_by_kind": _by_kind(attack, "kind"),
        "false_positive_rules": dict(Counter(
            rule for r in benign if LEVELS[r["level"]] >= 1 for rule in r["rules"])),
    }

    print(json.dumps(summary, indent=1, sort_keys=True))
    if args.verbose:
        for r in results:
            if r["label"] == "benign" and LEVELS[r["level"]] >= 1:
                print("FP", r["kind"], r["level"], r["points"], r["rules"], r["file"])
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary,
                       "sessions": [{k: v for k, v in r.items() if k != "file"}
                                    for r in results]}, fh, indent=1, sort_keys=True)
    return 0


def _by_kind(rows: list[dict], field: str) -> dict:
    out: dict[str, dict[str, int]] = {}
    for row in rows:
        bucket = out.setdefault(row[field], {"sessions": 0, "low": 0, "medium": 0,
                                             "high": 0, "critical": 0})
        bucket["sessions"] += 1
        bucket[row["level"]] += 1
    return out


if __name__ == "__main__":
    raise SystemExit(main())
