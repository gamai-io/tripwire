"""Behavioural detection for an inbound agent, on top of the access log.

Two layers:

1. The rules shipped in `gama-mandate` (`mandate.agentwatch`): tool switching,
   UA flipping, following a link that only existed in a document, key probing,
   reading submit-only endpoints, velocity, low-and-slow scanning.
2. The two things an *inbound* detector needs and an authorisation log cannot
   provide:
   - **canary hits** — any use of a planted key is decisive on its own;
   - **spec-derived novel paths** — a path whose first appearance follows a
     request for an API document within 60 seconds. A human does not move from
     reading a spec to a never-seen endpoint that fast; a script does.

Levels: any canary hit is `critical`; otherwise the mandate score applies
(>=6 high, >=3 medium). A judge model may explain a finding, never lower it.
"""
from __future__ import annotations

import time
import urllib.parse
from collections import defaultdict

from mandate import agentwatch
from mandate.core import append_receipt

from . import canary as canary_mod

SPEC_TOKENS = ("/openapi", "/swagger", "/docs", ".md", "/spec", "/redoc")


def is_doc_path(path: str) -> bool:
    p = (path or "").lower()
    return any(token in p for token in SPEC_TOKENS)


def spec_derived_paths(rows: list[dict], max_gap: float = 60.0) -> list[dict]:
    """First-time paths requested shortly after an API/spec document was fetched."""
    by_ip = defaultdict(list)
    for row in rows:
        by_ip[str(row.get("ip") or "?")].append(row)
    out = []
    for ip, items in by_ip.items():
        seen: set[str] = set()
        last_doc_ts: float | None = None
        for row in sorted(items, key=lambda r: float(r.get("ts") or 0)):
            path = str(row.get("path") or "")
            ts = float(row.get("ts") or 0)
            is_doc = is_doc_path(path)          # the path we served, not the Referer
            if not is_doc and path not in seen and last_doc_ts is not None \
                    and 0 <= ts - last_doc_ts <= max_gap:
                out.append({"ip": ip, "path": path, "ts": ts,
                            "seconds_after_doc": round(ts - last_doc_ts, 1)})
            if is_doc:
                last_doc_ts = ts
            seen.add(path)
    return out


def _raise_level(session: dict, points: int, level: str | None = None) -> None:
    session["points"] += points
    if session["points"] >= agentwatch.THRESHOLDS["high"]:
        session["level"] = "high"
    elif session["points"] >= agentwatch.THRESHOLDS["medium"]:
        session["level"] = "medium"
    if level is not None:
        session["level"] = level


def analyse(rows: list[dict], registry: dict | None = None, window: int = 600,
            now: float | None = None) -> dict:
    base = agentwatch.analyse(rows, window=window, now=now)

    canary_hits = []
    for row in rows:
        text = " ".join(str(row.get(k) or "") for k in
                        ("path", "ua", "referer", "query", "body", "auth"))
        text = urllib.parse.unquote(text)      # query strings arrive percent-encoded
        for hit in canary_mod.match(text, registry or {}):
            canary_hits.append({"ip": row.get("ip"), "ts": row.get("ts"),
                                "path": row.get("path"), "canary": hit.get("id")})

    spec_paths = spec_derived_paths(rows)
    for item in spec_paths:
        session = base["sessions"].get(item["ip"])
        if session is not None:
            session["findings"].append({
                "rule": "spec_derived_novel_path", "points": 3,
                "detail": "first request to %s %.1fs after an API document"
                          % (item["path"], item["seconds_after_doc"])})
            _raise_level(session, 3)

    for hit in canary_hits:
        session = base["sessions"].get(str(hit["ip"]))
        if session is not None:
            session["findings"].append({
                "rule": "canary_used", "points": 10,
                "detail": "planted key %s used on %s" % (hit["canary"], hit["path"])})
            _raise_level(session, 10, "critical")

    return {"window_s": window, "sources": base["sources"],
            "flagged": sum(1 for s in base["sessions"].values() if s["level"] != "low"),
            "canary_hits": canary_hits, "spec_derived_paths": spec_paths,
            "sessions": base["sessions"]}


def watch(log_path: str, registry: dict | None = None, window: int = 600,
          ledger: str | None = None) -> dict:
    rows = agentwatch.load(log_path)
    result = analyse(rows, registry, window)
    if ledger:
        alerts = {ip: s for ip, s in result["sessions"].items() if s["level"] != "low"}
        if alerts:
            append_receipt(ledger, {"v": 1, "type": "control", "action": "alert",
                                    "actor": "tripwire",
                                    "reason": "inbound agent behaviour",
                                    "ts": time.time(),
                                    "canary_hits": result["canary_hits"],
                                    "findings": alerts})
    return result
