"""Per-path baselines: a distributed scan looks like a normal Tuesday otherwise.

Every other rule is per source address. A patient scanner that sends two requests
per address from a thousand addresses is invisible to all of them — while the
endpoint itself sees a spike. This module keeps a small EWMA per path template
and reports paths whose distinct-source count jumps far above their own history.

It reports at the path level on purpose. The finding is "this endpoint is being
walked", not "address X is bad"; blaming individual addresses on a shared endpoint
is how a detector blocks a CDN.
"""
from __future__ import annotations

import json

from .strictjson import StrictJSONError, load_strict
import os
import re
import tempfile

SKIP_SUFFIXES = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                 ".woff", ".woff2", ".map", ".txt", ".xml")
_SEGMENT = re.compile(r"^(\d+|[0-9a-f]{8,}|[0-9a-f-]{16,}|\d{4}-\d{2}-\d{2})$", re.I)


def template(path: str) -> str:
    """`/api/v1/invoices/8812?x=1` -> `/api/v1/invoices/{}`."""
    clean = str(path or "/").split("?")[0].split("#")[0]
    parts = [p if not _SEGMENT.match(p) else "{}" for p in clean.split("/")]
    return "/".join(parts) or "/"


def skip(path: str) -> bool:
    return str(path or "").lower().endswith(SKIP_SUFFIXES)


def load(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {"version": 1, "paths": {}, "samples": 0}
    try:
        data = load_strict(path)
    except (OSError, StrictJSONError):
        return {"version": 1, "paths": {}, "samples": 0}
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return {"version": 1, "paths": {}, "samples": 0}
    return data


def _counts(rows: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for row in rows:
        path = str(row.get("path") or "/")
        if skip(path):
            continue
        key = template(path)
        item = out.setdefault(key, {"requests": 0, "ips": set()})
        item["requests"] += 1
        item["ips"].add(str(row.get("ip") or "?"))
    return {k: {"requests": v["requests"], "ips": len(v["ips"]),
                "sources": sorted(v["ips"])[:25]}
            for k, v in out.items()}


def update(rows: list[dict], baseline: dict, alpha: float = 0.2) -> dict:
    """Fold this window into the history. Cold paths take the first value whole."""
    counts = _counts(rows)
    paths = baseline.setdefault("paths", {})
    for key, item in counts.items():
        previous = paths.get(key)
        if previous is None:
            paths[key] = {"requests": item["requests"], "ips": item["ips"], "n": 1}
            continue
        n = int(previous.get("n") or 1) + 1
        paths[key] = {
            "requests": round((1 - alpha) * float(previous.get("requests") or 0)
                              + alpha * item["requests"], 3),
            "ips": round((1 - alpha) * float(previous.get("ips") or 0)
                         + alpha * item["ips"], 3),
            "n": n,
        }
    baseline["samples"] = int(baseline.get("samples") or 0) + 1
    baseline["updated"] = True
    return baseline


def anomalies(rows: list[dict], baseline: dict, factor: float = 3.0,
              floor_ips: int = 10) -> list[dict]:
    """Paths whose distinct-source count is far above their own baseline."""
    counts = _counts(rows)
    found = []
    for key, item in sorted(counts.items()):
        if item["ips"] < floor_ips:
            continue
        previous = (baseline.get("paths") or {}).get(key)
        expected = float((previous or {}).get("ips") or 0)
        if previous is None:
            continue                    # first sighting is not an anomaly
        if expected <= 0:
            expected = 0.5
        ratio = item["ips"] / expected
        if ratio >= factor:
            found.append({"path": key, "ips": item["ips"], "requests": item["requests"],
                          "baseline_ips": round(expected, 2),
                          "factor": round(ratio, 2),
                          # a 5x jump is a different operational event from a 3x one
                          "level": "high" if ratio >= max(5.0, factor * 1.5) else "medium",
                          "sources": item["sources"],
                          "sources_truncated": item["ips"] > len(item["sources"]),
                          "detail": "%d sources on %s, %.1fx its baseline of %.1f"
                                    % (item["ips"], key, ratio, expected)})
    return found


def save(path: str, baseline: dict) -> None:
    if not path:
        return
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    handle, tmp = tempfile.mkstemp(dir=directory or ".", prefix=".baseline-")
    with os.fdopen(handle, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)
