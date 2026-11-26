"""Behavioural detection for an inbound agent, on top of the access log.

Layer 1 — the rules shipped in `gama-mandate` (`mandate.agentwatch`): tool
switching, UA flipping, following a link that only existed in a document, key
probing, reading submit-only endpoints, velocity, low-and-slow scanning.

Layer 2 — what an inbound detector needs and an authorisation log cannot give:
  - **canaries**: any use of a planted key is decisive on its own;
  - **spec-derived novel paths**: a first request to a path right after an API
    document was served;
  - **auth failure streak**: five or more rejected credentials on one endpoint
    inside a minute;
  - **wide probe**: twenty-five or more distinct paths answering 4xx.

Layer 3 — corroboration. Reading documentation is not an attack: a developer
opens the spec and then calls the API with a key that works. So the two
document-related findings only count when the same address also **failed an
authentication check** (`401`/`403`) inside the window, or a canary fired. That
single condition is what separated the reported intruder from a normal reader,
and it is measured in `docs/FALSE_POSITIVES.md` rather than asserted here.

Levels: any canary hit is `critical`; otherwise >=6 high, >=3 medium.
A judge model may explain a finding, never lower it.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import tempfile
import time
import urllib.parse
from collections import defaultdict

from mandate import agentwatch
from mandate.core import append_receipt

from . import baseline as baseline_mod
from . import canary as canary_mod
from . import logread

SPEC_TOKENS = ("/openapi", "/swagger", "/docs", ".md", "/spec", "/redoc")
DOC_RULES = {"docs_link_follow", "spec_derived_novel_path"}
FAILED = (401, 403)
# tool_switch alone is a developer, not an intruder: measured at 50/300 benign
# sessions in docs/FALSE_POSITIVES.md, so it weighs 2 and needs corroboration.
WEIGHTS = {"tool_switch": 2}
HIGH, MEDIUM = agentwatch.THRESHOLDS["high"], agentwatch.THRESHOLDS["medium"]


def is_doc_path(path: str) -> bool:
    p = (path or "").lower()
    return any(token in p for token in SPEC_TOKENS)


def _level(points: int, critical: bool = False) -> str:
    if critical:
        return "critical"
    if points >= HIGH:
        return "high"
    if points >= MEDIUM:
        return "medium"
    return "low"


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
            status = int(row.get("status") or 0)
            if not is_doc and path not in seen and last_doc_ts is not None \
                    and 0 <= ts - last_doc_ts <= max_gap:
                out.append({"ip": ip, "path": path, "ts": ts,
                            "seconds_after_doc": round(ts - last_doc_ts, 1)})
                last_doc_ts = None      # one document, one followed link (the incident shape)
            if is_doc and status in (0, 200, 206):
                last_doc_ts = ts
            seen.add(path)
    return out


def auth_failure_streak(rows: list[dict], count: int = 5, within: float = 60.0) -> list[dict]:
    """Five or more rejected credentials on one path inside a minute."""
    by_key = defaultdict(list)
    for row in rows:
        if int(row.get("status") or 0) not in FAILED:
            continue
        by_key[(str(row.get("ip") or "?"), str(row.get("path") or ""))].append(
            float(row.get("ts") or 0))
    out = []
    for (ip, path), stamps in by_key.items():
        stamps.sort()
        left = 0
        best = (0, 0.0)
        for right, stamp in enumerate(stamps):
            while stamp - stamps[left] > within:
                left += 1
            window = right - left + 1
            if window > best[0]:
                best = (window, round(stamp - stamps[left], 1))
        if best[0] >= count:
            out.append({"ip": ip, "path": path, "attempts": best[0],
                        "seconds": best[1]})
    return out


def wide_probe(rows: list[dict], threshold: int = 25) -> list[dict]:
    """Many distinct paths answering 4xx from one address."""
    by_ip = defaultdict(set)
    for row in rows:
        if 400 <= int(row.get("status") or 0) < 500:
            by_ip[str(row.get("ip") or "?")].add(str(row.get("path") or ""))
    return [{"ip": ip, "paths": len(paths)} for ip, paths in by_ip.items()
            if len(paths) >= threshold]


def key_across_addresses(rows: list[dict], min_addresses: int = 3,
                         min_failures: int = 5) -> list[dict]:
    """One credential, several source addresses, and it keeps failing.

    This is the evasion that beats every per-address rule: rotate the IP and each
    address looks innocent. A shared *working* key from several egress addresses
    is normal infrastructure, so the rule needs the failures as well.
    """
    by_key: dict[str, dict] = {}
    for row in rows:
        value = str(row.get("auth") or "none").strip()
        if value in ("", "none", "-"):
            continue
        item = by_key.setdefault(value, {"key": value, "addresses": set(),
                                         "failures": 0, "requests": 0})
        item["requests"] += 1
        item["addresses"].add(str(row.get("ip") or "?"))
        if _status(row.get("status")) in FAILED:
            item["failures"] += 1
    out = []
    for value, item in by_key.items():
        if len(item["addresses"]) < min_addresses or item["failures"] < min_failures:
            continue
        if item["requests"] and item["failures"] / item["requests"] < 0.25:
            continue          # a working key used from several offices is not theft
        out.append({"key": value, "addresses": sorted(item["addresses"]),
                    "failures": item["failures"], "requests": item["requests"]})
    return out


def _status(value) -> int:
    """A collector bug must not take the detector down with a ValueError."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return -1


def _ts(value):
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return None


def _failed_here(rows: list[dict]) -> bool:
    return any(_status(r.get("status")) in FAILED for r in rows)


def _corroborate(session: dict, failure: bool, canary: bool) -> None:
    """Demote document findings when nothing else about the session is suspicious."""
    if failure or canary:
        return
    kept = []
    for finding in session["findings"]:
        if finding["rule"] in DOC_RULES:
            finding = dict(finding)
            finding["suppressed"] = True
            finding["why"] = ("documentation reading without a failed auth check; "
                              "not counted")
            session["points"] -= finding["points"]
        kept.append(finding)
    session["findings"] = kept
    session["level"] = _level(max(0, session["points"]))


def analyse(rows: list[dict], registry: dict | None = None, window: int = 600,
            now: float | None = None) -> dict:
    moment = time.time() if now is None else float(now)
    valid, invalid = [], 0
    for row in rows:
        ts = _ts(row.get("ts"))
        if ts is None:
            invalid += 1
            continue
        clean = dict(row)
        clean["ts"] = ts
        clean["status"] = _status(row.get("status"))
        valid.append(clean)
    rows = valid
    in_window = [r for r in rows
                 if (window <= 0 or moment - float(r.get("ts") or 0) <= window)
                 and float(r.get("ts") or 0) <= moment + 300]
    base = agentwatch.analyse(in_window, window=window, now=moment)
    by_ip = defaultdict(list)
    for row in in_window:
        by_ip[str(row.get("ip") or "?")].append(row)

    canary_hits = []
    for row in rows:
        text = " ".join(str(row.get(k) or "") for k in
                        ("path", "ua", "referer", "query", "body", "auth"))
        text = urllib.parse.unquote(text)      # query strings arrive percent-encoded
        for hit in canary_mod.match(text, registry or {}):
            canary_hits.append({"ip": row.get("ip"), "ts": row.get("ts"),
                                "path": row.get("path"), "canary": hit.get("id")})

    for item in spec_derived_paths(in_window):
        session = base["sessions"].get(item["ip"])
        if session is not None:
            session["findings"].append({
                "rule": "spec_derived_novel_path", "points": 3,
                "detail": "first request to %s %.1fs after an API document"
                          % (item["path"], item["seconds_after_doc"])})
            session["points"] += 3
            session["level"] = _level(session["points"])

    for cluster in key_across_addresses(in_window):
        for ip in cluster["addresses"]:
            session = base["sessions"].get(ip)
            if session is None:
                continue
            wide = len(cluster["addresses"]) >= 6 or cluster["failures"] >= 20
            weight = 6 if wide else 3
            session["findings"].append({
                "rule": "key_across_addresses", "points": weight,
                "detail": "the same credential was used from %d addresses with %d rejected "
                          "requests" % (len(cluster["addresses"]), cluster["failures"])})
            session["points"] += weight
            session["level"] = _level(session["points"])

    for item in auth_failure_streak(in_window):
        session = base["sessions"].get(item["ip"])
        if session is not None:
            session["findings"].append({
                "rule": "auth_failure_streak", "points": 4,
                "detail": "%d rejected credentials on %s in %.0fs"
                          % (item["attempts"], item["path"], max(item["seconds"], 1))})
            session["points"] += 4
            session["level"] = _level(session["points"])

    for item in path_burst(in_window):
        session = base["sessions"].get(item["ip"])
        if session is not None:
            session["findings"].append({
                "rule": "path_burst", "points": 3,
                "detail": "%d distinct paths in %ds" % (item["paths"], item["seconds"])})
            session["points"] += 3
            session["level"] = _level(session["points"])

    for item in wide_probe(in_window):
        session = base["sessions"].get(item["ip"])
        if session is not None:
            session["findings"].append({
                "rule": "wide_probe", "points": 2,
                "detail": "%d distinct paths answered 4xx" % item["paths"]})
            session["points"] += 2
            session["level"] = _level(session["points"])

    for hit in canary_hits:
        ip = str(hit["ip"])
        session = base["sessions"].get(ip)
        if session is None:      # a canary alone is enough to open a case
            session = base["sessions"][ip] = {"points": 0, "level": "low",
                                              "findings": [], "requests": 0,
                                              "first_ts": hit.get("ts"),
                                              "last_ts": hit.get("ts")}
        if session is not None:
            session["findings"].append({
                "rule": "canary_used", "points": 10,
                "detail": "planted key %s used on %s" % (hit["canary"], hit["path"])})
            session["points"] += 10
            session["level"] = "critical"

    for session in base["sessions"].values():
        for finding in session["findings"]:
            want = WEIGHTS.get(finding["rule"])
            if want is not None and finding["points"] != want:
                session["points"] += want - finding["points"]
                finding["points"] = want
        session["level"] = _level(max(0, session["points"]),
                                  session["level"] == "critical")

    for ip, session in base["sessions"].items():
        hit = any(str(h["ip"]) == ip for h in canary_hits)
        _corroborate(session, _failed_here(by_ip.get(ip, [])), hit)

    evidence = {}
    for ip, items in by_ip.items():
        evidence[ip] = {
            "requests": len(items),
            "failures": sum(1 for r in items if _status(r.get("status")) in FAILED),
            "user_agents": len({str(r.get("ua") or "") for r in items}),
        }

    return {"window_s": window, "sources": base["sources"], "evidence": evidence,
            "rows_in_window": len(in_window), "invalid_rows": invalid,
            "xff_ignored": sum(1 for r in rows if r.get("xff_ignored")),
            "flagged": sum(1 for s in base["sessions"].values() if s["level"] != "low"),
            "canary_hits": canary_hits, "spec_derived_paths": spec_derived_paths(in_window),
            "auth_failure_streaks": auth_failure_streak(in_window),
            "key_clusters": key_across_addresses(in_window),
            "sessions": base["sessions"]}


def _merge_session(into: dict, session: dict) -> None:
    """Union findings by rule, keep the highest points. Used by chunked scoring."""
    known = {f["rule"]: f for f in into["findings"]}
    for finding in session.get("findings") or []:
        previous = known.get(finding["rule"])
        if previous is None or finding["points"] > previous["points"]:
            known[finding["rule"]] = finding
    into["points"] = max(into["points"], session["points"])
    into["findings"] = list(known.values())
    into["requests"] += session.get("requests", 0)
    into["first_ts"] = min(filter(None, [into.get("first_ts"),
                                         session.get("first_ts")]), default=None)
    into["last_ts"] = max(filter(None, [into.get("last_ts"),
                                        session.get("last_ts")]), default=None)
    into["level"] = _level(into["points"], into["level"] == "critical"
                           or session["level"] == "critical")


def watch_stream(log_path: str, registry: dict | None = None, window: int = 600,
                 ledger: str | None = None, fmt: str = "auto",
                 now: float | None = None, trusted: list | None = None,
                 chunk: int = 200_000, baseline_path: str = "",
                 baseline_factor: float = 3.0, baseline_floor: int = 10,
                 baseline_update: bool = True,
                 min_level: str = "medium", state_path: str = "",
                 state_ttl: int = 3600, exceptions: list | None = None,
                 max_sources: int = 200_000) -> dict:
    """Score a file too large to hold: keep only the window, merge per chunk.

    Memory is bounded by (sources inside the window), not by the file: sessions
    that have left the window and are not flagged are dropped. Findings are
    unioned per source and points take the maximum, so a chunk boundary can lose a
    timing correlation between two rules but never invents one.
    """
    if window <= 0:
        # "no window" means the whole file; a stream that trims by a window of
        # zero would drop every row except the newest and call it clean
        plain = watch(log_path, registry, window=0, ledger=ledger, fmt=fmt,
                      now=now, trusted=trusted, min_level=min_level,
                      state_path=state_path, state_ttl=state_ttl,
                      exceptions=exceptions, baseline_path=baseline_path,
                      baseline_factor=baseline_factor,
                      baseline_floor=baseline_floor,
                      baseline_update=baseline_update)
        plain["stream"] = False
        plain["chunk"] = chunk
        return plain
    from collections import deque
    kept: deque = deque()
    merged: dict[str, dict] = {}
    canary_hits: list[dict] = []
    anomalies: dict[str, dict] = {}
    total = skipped = future = overflow = 0
    latest = 0.0
    last_ts = float("-inf")
    max_sources = max(1, int(max_sources))
    moment = float(now) if now is not None else time.time()
    since_analysis = 0
    rows_seen: list[dict] = []
    stream_canaries: list[dict] = []
    read_stats: dict = {}

    def analyse_window(final: bool = False) -> None:
        rows = list(kept)
        if not rows:
            return
        nonlocal overflow
        result = analyse(rows, None, window, now=latest + 1)
        for ip, session in result["sessions"].items():
            if ip not in merged and len(merged) >= max_sources:
                # a source-rotating flood cannot be scored honestly; refusing is
                # better than dropping half of it and reporting "clean"
                overflow += 1
                continue
            target = merged.setdefault(ip, {"points": 0, "level": "low", "findings": [],
                                            "requests": 0, "first_ts": None,
                                            "last_ts": None})
            _merge_session(target, session)
        canary_hits.extend(result["canary_hits"])
        for item in result.get("path_anomalies") or []:
            anomalies[item["path"]] = item
        if final:
            rows_seen.extend(rows)

    for row in logread.iter_rows(log_path, fmt, trusted, stats=read_stats):
        total += 1
        text = " ".join(str(row.get(k) or "") for k in
                        ("path", "ua", "referer", "query", "body", "auth"))
        text = urllib.parse.unquote(text)
        for hit in canary_mod.match(text, registry or {}):
            stream_canaries.append({"ip": row.get("ip"), "ts": row.get("ts"),
                                    "path": row.get("path"),
                                    "canary": hit.get("id")})
        ts = _ts(row.get("ts"))
        if ts is None:
            skipped += 1
            continue
        if ts > moment + 60:          # clock skew or a poisoned collector
            future += 1
            skipped += 1
            continue
        latest = max(latest, ts)
        cutoff = latest - window
        if ts < cutoff:
            skipped += 1          # already outside the window; never enter it
            continue
        kept.append(row)
        if ts < last_ts:
            # a collector that writes out of order must not leave stale rows in
            # the deque forever: re-order once, then prune by timestamp
            kept = deque(sorted(kept, key=lambda r: _ts(r.get("ts")) or 0))
        last_ts = max(last_ts, ts)
        since_analysis += 1
        while kept and float(kept[0].get("ts") or 0) < cutoff:
            kept.popleft()
        # bound memory by sources in the window, not by every source ever seen
        if cutoff > 0:
            for ip in [ip for ip, sess in merged.items()
                       if sess.get("level") == "low"
                       and float(sess.get("last_ts") or 0) < cutoff]:
                del merged[ip]
        if since_analysis >= max(1, min(chunk, max_sources)):
            analyse_window()
            since_analysis = 0
            if overflow:
                break
        if len(kept) > chunk * 2:          # a burst: keep memory bounded, note it
            skipped += len(kept) - chunk
            while len(kept) > chunk:
                kept.popleft()
    if not overflow:
        analyse_window(final=True)
    if overflow:
        return {"window_s": window, "sources": len(merged), "rows": total,
                "skipped_lines": skipped, "future_rows": future, "empty": total == 0,
                "stream": True, "chunk": chunk, "rows_in_window": len(kept),
                "canary_hits": canary_hits, "sessions": merged,
                "flagged": 0, "error": "too many distinct sources (>%d); "
                "refusing to report a partial analysis" % max_sources,
                "oversize_lines": read_stats.get("oversize", 0),
                "bad_timestamps": read_stats.get("bad_timestamps", 0),
                "duplicate_keys": read_stats.get("duplicate_keys", 0),
                "path_anomalies": [], "now": latest}
    # lines the reader refused (oversize, duplicate keys, bad timestamps) are
    # part of the skipped total: a run that hid them would look cleaner than it is
    skipped += int(read_stats.get("skipped") or 0)
    for hit in stream_canaries:
        ip = str(hit["ip"])
        if ip not in merged and len(merged) >= max_sources:
            # a canary outside the window still must not push the run past the cap
            overflow += 1
            continue
        canary_hits.append(hit)
        session = merged.get(ip)
        if session is None:
            session = merged[ip] = {"points": 10, "level": "critical",
                                    "findings": [], "requests": 0,
                                    "first_ts": hit.get("ts"),
                                    "last_ts": hit.get("ts")}
        session.setdefault("findings", []).append({
            "rule": "canary_used", "points": 10,
            "detail": "planted key %s used on %s" % (hit["canary"], hit["path"])})
        session["points"] = max(int(session.get("points") or 0), 10)
        session["level"] = "critical"
    if overflow:
        return {"window_s": window, "sources": len(merged), "rows": total,
                "skipped_lines": skipped, "future_rows": future, "empty": total == 0,
                "stream": True, "chunk": chunk, "rows_in_window": len(kept),
                "canary_hits": canary_hits, "sessions": merged,
                "flagged": 0, "error": "too many distinct sources (>%d); "
                "refusing to report a partial analysis" % max_sources,
                "oversize_lines": read_stats.get("oversize", 0),
                "bad_timestamps": read_stats.get("bad_timestamps", 0),
                "duplicate_keys": read_stats.get("duplicate_keys", 0),
                "path_anomalies": [], "now": latest}
    rows = rows_seen if baseline_path else []
    result = {"window_s": window, "sources": len(merged), "rows": total,
              "skipped_lines": skipped, "future_rows": future, "empty": total == 0,
              "stream": True, "chunk": chunk,
              "oversize_lines": read_stats.get("oversize", 0),
              "bad_timestamps": read_stats.get("bad_timestamps", 0),
              "duplicate_keys": read_stats.get("duplicate_keys", 0),
              "rows_in_window": len(kept),
              "canary_hits": canary_hits,
              "auth_failure_streaks": [],
              "spec_derived_paths": [],
              "path_anomalies": [],
              "flagged": sum(1 for s in merged.values() if s["level"] != "low"),
              "sessions": merged,
              "evidence": {ip: {"requests": s.get("requests", 0), "failures": 0,
                                "user_agents": 0} for ip, s in merged.items()},
              "now": latest}
    if baseline_path:
        _apply_baseline(result, rows, baseline_path, baseline_factor, baseline_floor,
                        baseline_update)
    if exceptions:
        result = apply_exceptions(result, exceptions, now=now or time.time())
    _drop_excepted_paths(result)
    state = None
    if state_path:
        state = mark_state(result, state_path, ttl_s=state_ttl, now=now,
                           min_level=min_level)
    result["state_applied"] = bool(state_path)
    _write_alert_records(result, ledger, log_path, min_level, extra={"stream": True})
    if state is not None:
        _save_state_or_warn(state_path, state, result)
    return result


def watch_rows(rows: list[dict], registry: dict | None = None, window: int = 600,
               now: float | None = None, baseline_path: str = "",
               baseline_factor: float = 3.0, baseline_floor: int = 10,
               baseline_update: bool = True) -> dict:
    """Score rows you already have (tests, notebooks, another collector)."""
    result = analyse(rows, registry, window, now=now)
    _apply_baseline(result, rows, baseline_path, baseline_factor, baseline_floor,
                    baseline_update)
    result["rows"] = len(rows)
    result["empty"] = not rows
    return result


def _apply_baseline(result: dict, rows: list[dict], path: str, factor: float,
                    floor: int, update: bool) -> None:
    if not path:
        result["path_anomalies"] = []
        return
    history = baseline_mod.load(path)
    found = baseline_mod.anomalies(rows, history, factor, floor)
    result["path_anomalies"] = found
    if update:
        flagged = {item["path"] for item in found}
        clean = [r for r in rows
                 if baseline_mod.template(str(r.get("path") or "/")) not in flagged]
        baseline_mod.update(clean, history)
        # one anomalous window must not poison the history, but an event that
        # repeats for two windows is the new normal: fold it in then, so the
        # same path cannot alert forever.
        paths = history.setdefault("paths", {})
        for item in found:
            entry = paths.get(item["path"])
            if entry is None:
                continue
            entry["strikes"] = int(entry.get("strikes") or 0) + 1
            if entry["strikes"] >= 2:
                entry["requests"] = round(0.8 * float(entry.get("requests") or 0)
                                          + 0.2 * item["requests"], 3)
                entry["ips"] = round(0.8 * float(entry.get("ips") or 0)
                                     + 0.2 * item["ips"], 3)
        for key, entry in paths.items():
            if key not in flagged and "strikes" in entry:
                entry.pop("strikes", None)
        baseline_mod.save(path, history)


def _drop_excepted_paths(result: dict) -> None:
    """A path anomaly whose every source is on an active exception is ours."""
    if not result.get("exceptions_active"):
        return
    excepted = {ip for ip, session in result.get("sessions", {}).items()
                if session.get("exception")}
    kept = []
    for item in result.get("path_anomalies") or []:
        sources = item.get("sources") or []
        if (sources and not item.get("sources_truncated")
                and set(sources) <= excepted):
            continue
        kept.append(item)
    result["path_anomalies"] = kept


def _write_alert_records(result: dict, ledger: str | None, log_path: str,
                         min_level: str, extra: dict | None = None) -> list[str]:
    """Append only what the operator asked to see, at the requested floor.

    Path anomalies and session alerts share one floor; with `--state`, both are
    written only when they are new or worse.
    """
    if not ledger:
        return []
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    floor = order.get(min_level, 1)
    wrote = []
    new_paths = [item for item in result.get("path_anomalies") or []
                 if item.get("is_new", True)
                 and order.get(item.get("level", "high"), 2) >= floor]
    if new_paths:
        level = max((item.get("level", "high") for item in new_paths),
                    key=lambda name: order.get(name, 0))
        append_receipt(ledger, dict({
            "v": 1, "type": "control", "action": "alert", "actor": "tripwire",
            "kind": "path_anomaly", "level": level, "min_level": min_level,
            "reason": "distributed scan across sources",
            "ts": time.time(), "log": log_path,
            "paths": new_paths}, **(extra or {})))
        wrote.append("path_anomaly")
    state_applied = bool(result.get("state_applied"))
    alerts = {ip: session for ip, session in result["sessions"].items()
              if order.get(session["level"], 0) >= floor
              and (not state_applied or session.get("is_new"))}
    if alerts:
        append_receipt(ledger, dict({
            "v": 1, "type": "control", "action": "alert", "actor": "tripwire",
            "reason": "inbound agent behaviour", "min_level": min_level,
            "ts": time.time(), "log": log_path,
            "canary_hits": result["canary_hits"],
            "findings": alerts}, **(extra or {})))
        wrote.append("session")
    return wrote


def watch(log_path: str, registry: dict | None = None, window: int = 600,
          ledger: str | None = None, fmt: str = "auto",
          now: float | None = None, trusted: list | None = None,
          min_level: str = "medium", state_path: str = "",
          state_ttl: int = 3600, exceptions: list | None = None,
          max_sources: int = 200_000,
          baseline_path: str = "", baseline_factor: float = 3.0,
          baseline_floor: int = 10, baseline_update: bool = True) -> dict:
    """Score a file.

    `now` defaults to the newest row in the file, so a log written yesterday is
    still analysed instead of silently producing "0 sources, 0 flagged". Pass
    `now=time.time()` for live tailing.
    """
    rows, stats = logread.load_stats(log_path, fmt, trusted)
    if now is None and rows:
        # a single future-dated line must not blind the whole run
        now = min(max(float(r.get("ts") or 0) for r in rows) + 1, time.time() + 60)
    result = analyse(rows, registry, window, now=now)
    if len(result.get("sessions") or {}) > max(1, int(max_sources)):
        result["error"] = ("too many distinct sources (>%d); refusing to report a "
                           "partial analysis" % max_sources)
        result["sources"] = len(result.get("sessions") or {})
        result["rows"] = len(rows)
        result["now"] = now
        return result
    in_window = [r for r in rows
                 if (window <= 0 or now - float(r.get("ts") or 0) <= window)
                 and float(r.get("ts") or 0) <= now + 300]
    _apply_baseline(result, in_window, baseline_path, baseline_factor,
                    baseline_floor, baseline_update)

    result["rows"] = len(rows)
    result["skipped_lines"] = stats.get("skipped", 0) + result.get("invalid_rows", 0)
    result["oversize_lines"] = stats.get("oversize", 0)
    result["bad_timestamps"] = stats.get("bad_timestamps", 0)
    result["duplicate_keys"] = stats.get("duplicate_keys", 0)
    result["log_format"] = stats.get("format")
    result["empty"] = not rows
    result["now"] = now
    if exceptions:
        result = apply_exceptions(result, exceptions, now=now)
    _drop_excepted_paths(result)
    state = None
    if state_path:
        state = mark_state(result, state_path, ttl_s=state_ttl, now=now,
                           min_level=min_level)
    result["state_applied"] = bool(state_path)
    _write_alert_records(result, ledger, log_path, min_level)
    if state is not None:
        _save_state_or_warn(state_path, state, result)
    return result


def _blockable(ip: str) -> bool:
    """Only global unicast addresses may be denied.

    A loopback or private address in the log is our own health check, our own
    scanner, or a reverse proxy: blocking it would take the service down, not
    the intruder. The denial is therefore skipped and reported, never quietly
    applied.
    """
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


GOOD_BOTS = ("googlebot", "bingbot", "duckduckbot", "yandexbot", "applebot",
             "facebookexternalhit", "twitterbot", "linkedinbot", "uptime")


def path_burst(rows: list[dict], threshold: int = 40, within: float = 60.0) -> list[dict]:
    """Many *first-seen* paths in a minute, whatever the status code.

    Status-independent on purpose: a scanner behind a redirect-heavy vhost
    answers 301 to everything and never trips the 4xx rules.

    A crawler UA is not a free pass: `curl -A Googlebot` walks the site freely
    unless being a real crawler is corroborated. The signal is that a real
    crawler does not collect `401`/`403` while walking, so the exemption only
    applies to an address with no failed auth in the window.
    """
    failures: dict[str, int] = defaultdict(int)
    for row in rows:
        if _status(row.get("status")) in FAILED:
            failures[str(row.get("ip") or "?")] += 1
    by_ip = defaultdict(list)
    for row in rows:
        ip = str(row.get("ip") or "?")
        ua = str(row.get("ua") or "").lower()
        if any(bot in ua for bot in GOOD_BOTS) and not failures.get(ip):
            continue
        by_ip[ip].append((float(row.get("ts") or 0),
                          str(row.get("path") or "")))
    out = []
    for ip, items in by_ip.items():
        items.sort()
        counts: dict[str, int] = {}
        left = 0
        for ts, path in items:
            counts[path] = counts.get(path, 0) + 1
            while ts - items[left][0] > within:
                old = items[left][1]
                counts[old] -= 1
                if not counts[old]:
                    del counts[old]
                left += 1
            if len(counts) >= threshold:
                out.append({"ip": ip, "paths": len(counts), "seconds": int(within)})
                break
    return out


IDENTITY_RULES = {"canary_used", "key_probing", "auth_failure_streak",
                  "key_across_addresses"}
BEHAVIOUR_RULES = {"ua_flip", "tool_switch", "docs_link_follow",
                   "spec_derived_novel_path", "read_after_submit"}


def deny_evidence(session: dict, evidence: dict | None) -> tuple[bool, str]:
    """Blocking an address is a bigger decision than alerting on it.

    Volume rules (`velocity`, `wide_probe`, `low_and_slow_scan`) fire on shared
    egress — a CDN, a corporate NAT, a hospital with one line — so they can alert
    but not deny. Denial needs identity evidence: a canary, a probed key, or
    rejected credentials. Behaviour-only and volume-only findings never deny.

    `evidence` is kept for callers that pass it, but the decision does not use it:
    volume is exactly what a shared NAT produces.
    """
    rules = {f["rule"] for f in session.get("findings") or [] if not f.get("suppressed")}
    if "canary_used" in rules:
        return True, "canary"
    if rules & IDENTITY_RULES:
        return True, "identity evidence: %s" % ",".join(sorted(rules & IDENTITY_RULES))
    # Behaviour alone is never enough to block an address: a shared NAT with a
    # laptop, a phone and one curl script looks exactly like this. Alerts stay.
    behaviours = rules & BEHAVIOUR_RULES
    if behaviours:
        return False, "behaviour only (%s); alert, not block" % ",".join(sorted(behaviours))
    return False, "volume evidence only (%s)" % (",".join(sorted(rules)) or "none")


def mark_state(result: dict, state_path: str, ttl_s: int = 3600,
               now: float | None = None, min_level: str = "medium") -> dict:
    """Mark what is new or worse since the last run, without writing the file.

    Sessions and path anomalies are both remembered; the caller appends the
    ledger records first and saves the state after, so a failed ledger write
    cannot silently suppress the alert forever.
    """
    moment = time.time() if now is None else now
    state = {"version": 1, "alerts": {}, "paths": {}}
    if os.path.exists(state_path):
        try:
            loaded = json.load(open(state_path, encoding="utf-8"))
            if isinstance(loaded, dict):
                state.update(loaded)
        except ValueError:
            pass
    alerts = state.setdefault("alerts", {})
    paths = state.setdefault("paths", {})
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    new_sessions = 0
    floor = order.get(min_level, 1)
    for ip, session in result["sessions"].items():
        if order.get(session["level"], 0) < floor:
            continue
        previous = alerts.get(ip)
        expired = not previous or float(previous.get("expires") or 0) <= moment
        worse = bool(previous) and order.get(session["level"], 0) > order.get(
            previous.get("level"), 0)
        session["is_new"] = bool(expired or worse)
        if session["is_new"]:
            new_sessions += 1
        else:
            session["repeat"] = True
        alerts[ip] = {"level": session["level"], "points": session["points"],
                      "first_seen": (previous or {}).get("first_seen", int(moment)),
                      "expires": int(moment + ttl_s)}
    new_paths = 0
    for item in result.get("path_anomalies") or []:
        key = str(item.get("path") or "?")
        previous = paths.get(key)
        sources = item.get("sources") or []
        fingerprint = "%d:%s%s" % (
            item.get("ips") or 0, ",".join(str(s) for s in sources[:25]),
            "..." if item.get("sources_truncated") else "")
        expired = not previous or float(previous.get("expires") or 0) <= moment
        worse = bool(previous) and order.get(item.get("level", "high"), 2) > order.get(
            previous.get("level"), 2)
        changed = bool(previous) and previous.get("sources") != fingerprint
        item["is_new"] = bool(expired or worse or changed)
        if item["is_new"]:
            new_paths += 1
        else:
            item["repeat"] = True
        paths[key] = {"level": item.get("level", "high"),
                      "sources": fingerprint,
                      "first_seen": (previous or {}).get("first_seen", int(moment)),
                      "expires": int(moment + ttl_s)}
    state["alerts"] = {ip: item for ip, item in alerts.items()
                       if float(item.get("expires") or 0) > moment}
    state["paths"] = {key: item for key, item in paths.items()
                      if float(item.get("expires") or 0) > moment}
    result["new_alerts"] = new_sessions + new_paths
    result["new_path_anomalies"] = [item["path"] for item in
                                    result.get("path_anomalies") or []
                                    if item.get("is_new")]
    return state


def save_state(state_path: str, state: dict) -> None:
    directory = os.path.dirname(os.path.abspath(state_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    handle, tmp = tempfile.mkstemp(dir=directory or ".", prefix=".state-")
    with os.fdopen(handle, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(tmp, state_path)


def _save_state_or_warn(state_path: str, state: dict, result: dict) -> None:
    """The ledger record is already written; a state failure must be loud, not fatal."""
    try:
        save_state(state_path, state)
    except OSError as exc:
        result["state_error"] = str(exc)
        print("tripwire: state not saved (%s); the same alert may repeat"
              % exc, file=sys.stderr)


def apply_state(result: dict, state_path: str, ttl_s: int = 3600,
                now: float | None = None) -> dict:
    """Return only what is new or worse since the last run, and remember it.

    A cron that re-runs every minute would otherwise re-alert on the same address
    until the window rolls over. State is a small JSON file; it is pruned on every
    write, so it cannot grow without bound.
    """
    state = mark_state(result, state_path, ttl_s=ttl_s, now=now)
    save_state(state_path, state)
    result["state_applied"] = True
    return result


DENY_ENTRY = re.compile(
    r"^# (?P<ip>\S+) (?P<level>\w+) points=(?P<points>\d+) expires=(?P<expires>\d+) "
    r"rules=(?P<rules>\S*) reason=(?P<reason>.*)$")


def read_deny_map(path: str) -> dict:
    """Entries of a list we wrote earlier, including ones written by another run."""
    entries: dict[str, dict] = {}
    if not path or not os.path.exists(path):
        return entries
    lines = open(path, encoding="utf-8").read().splitlines()
    for index, line in enumerate(lines):
        match = DENY_ENTRY.match(line)
        if not match or index + 1 >= len(lines):
            continue
        if lines[index + 1].strip() != "deny %s;" % match.group("ip"):
            continue
        entries[match.group("ip")] = {
            "ip": match.group("ip"), "level": match.group("level"),
            "points": int(match.group("points")),
            "expires": int(match.group("expires")),
            "rules": [r for r in match.group("rules").split(",") if r],
            "reason": match.group("reason"),
        }
    return entries


def load_exceptions(path: str) -> list[dict]:
    """A whitelist that expires, says who allowed it and why.

    An exception without an expiry is a permanent hole nobody remembers; without a
    name it is unattributable. Both are required here.
    """
    if not path or not os.path.exists(path):
        return []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return []
    items = data.get("exceptions") if isinstance(data, dict) else data
    out = []
    for item in items or []:
        if not isinstance(item, dict) or not item.get("ip"):
            continue
        if not item.get("until") or not item.get("approver"):
            continue          # reject silently-incomplete exceptions
        out.append({"ip": str(item["ip"]), "until": int(item["until"]),
                    "approver": str(item["approver"]),
                    "reason": str(item.get("reason") or "")})
    return out


def apply_exceptions(result: dict, exceptions: list[dict],
                     now: float | None = None) -> dict:
    moment = time.time() if now is None else float(now)
    active = {item["ip"]: item for item in exceptions if int(item["until"]) > moment}
    for ip, session in result["sessions"].items():
        item = active.get(ip)
        if item:
            session["exception"] = {"until": item["until"],
                                    "approver": item["approver"],
                                    "reason": item.get("reason", "")}
    result["exceptions_active"] = len(active)
    return result


def _clean(text, limit: int = 120) -> str:
    """Anything we write into a config file is data, not config."""
    return re.sub(r"[\r\n\t]+", " ", str(text or ""))[:limit]


def deny_list(result: dict, min_level: str = "medium", now: float | None = None,
              ttl_s: int = 3600, ignore: set[str] | None = None,
              allow_volume: bool = False, previous: dict | None = None,
              cap: int = 1000, exceptions: list | None = None) -> dict:
    """Turn findings into an edge block list (nginx `deny` lines + JSON entries).

    The list is meant to be rewritten on a timer: every entry carries the epoch
    when it should disappear, so a cron that re-runs `tripwire watch --deny-map`
    both adds and removes addresses without a second mechanism.
    """
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    floor = order.get(min_level, 1)
    moment = time.time() if now is None else now
    entries = []
    skipped = []
    ignore = ignore or set()
    for ip, session in sorted(result["sessions"].items()):
        if order.get(session["level"], 0) < floor:
            continue
        if session.get("exception"):
            skipped.append({"ip": ip, "level": session["level"],
                            "why": "exception until %s (%s)"
                                   % (session["exception"].get("until"),
                                      session["exception"].get("approver"))})
            continue
        if ip in ignore or not _blockable(ip):
            skipped.append({"ip": ip, "level": session["level"],
                            "why": "ignored" if ip in ignore else "not a global address"})
            continue
        ok, why = deny_evidence(session, (result.get("evidence") or {}).get(ip))
        if not ok and not allow_volume:
            skipped.append({"ip": ip, "level": session["level"], "why": why})
            continue
        entries.append({"ip": ip, "level": session["level"], "points": session["points"],
                        "reason": why, "expires": int(moment + ttl_s),
                        "rules": sorted({f["rule"] for f in session["findings"]
                                         if not f.get("suppressed")})})
    # an active exception or an ignore entry must lift a block that is already
    # on disk, not only prevent a new one
    active_excepted = {str(item.get("ip")) for item in (exceptions or [])
                       if float(item.get("until") or 0) > moment}
    active_excepted |= set(ignore)
    active_excepted |= {ip for ip, session in result["sessions"].items()
                        if session.get("exception")}
    # keep what an earlier run blocked and has not expired, but re-validate it:
    # a file on disk is untrusted input, not a list to trust
    merged = {}
    for ip, item in (previous or {}).items():
        if ip in active_excepted or not _blockable(ip):
            continue
        try:
            expires = int(item.get("expires") or 0)
        except (TypeError, ValueError):
            continue
        if expires <= moment:
            continue
        merged[ip] = {"ip": ip, "level": _clean(item.get("level"), 10) or "medium",
                      "points": int(item.get("points") or 0),
                      "expires": expires,
                      "rules": sorted({_clean(r, 40) for r in (item.get("rules") or [])
                                       if _clean(r, 40)}),
                      "reason": _clean(item.get("reason"))}
    order_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for entry in entries:
        old = merged.get(entry["ip"])
        if old is None or order_levels.get(entry["level"], 0) >= order_levels.get(
                old.get("level"), 0):
            merged[entry["ip"]] = entry
    if len(merged) > cap:
        return {"entries": [], "count": 0, "skipped": skipped,
                "previous": len(previous or {}),
                "nginx": "# refused: %d entries exceed cap %d\n" % (len(merged), cap),
                "json": {"error": "cap_exceeded", "entries": len(merged), "cap": cap},
                "error": "deny cap exceeded (%d > %d); nothing written"
                         % (len(merged), cap)}
    lines = ["# tripwire deny list, generated %s, ttl %ds"
             % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(moment)), ttl_s)]
    for entry in merged.values():
        lines.append("# %s %s points=%d expires=%d rules=%s reason=%s"
                     % (entry["ip"], entry["level"], entry["points"], entry["expires"],
                        ",".join(entry["rules"]), _clean(entry.get("reason"))))
        lines.append("deny %s;" % entry["ip"])
    for item in skipped:
        lines.append("# skipped %s (%s)" % (item["ip"], _clean(item.get("why"))))
    return {"entries": list(merged.values()), "count": len(merged), "skipped": skipped,
            "nginx": "\n".join(lines) + "\n",
            "json": {"generated": int(moment), "ttl_s": ttl_s,
                     "deny": list(merged.values())}}


def read_deny_json(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out = {}
    for item in data.get("deny") or []:
        if isinstance(item, dict) and item.get("ip"):
            out[str(item["ip"])] = item
    return out


def _acquire_lock(path: str):
    """Serialise read-merge-write across processes; a lost update drops a block."""
    if not path:
        return None
    try:
        import fcntl
    except ImportError:          # Windows: no flock; the timer is single writer there
        return None
    try:
        handle = open(path + ".lock", "a+")
        fcntl.flock(handle, fcntl.LOCK_EX)
        return handle
    except OSError:
        return None


def _release_lock(handle) -> None:
    if handle is None:
        return
    try:
        import fcntl
        fcntl.flock(handle, fcntl.LOCK_UN)
    except (ImportError, OSError):
        pass
    try:
        handle.close()
    except OSError:
        pass


def write_deny_files(result: dict, map_path: str | None, json_path: str | None,
                     **kwargs) -> dict:
    """Merge with what is on disk under a lock, then replace atomically.

    The map is the source of truth (the apply unit watches it); the JSON copy is
    written after it and its failure is reported, not treated as a refusal.
    """
    lock = _acquire_lock(map_path or json_path or "")
    staged: list[tuple[str, str]] = []
    try:
        previous = read_deny_map(map_path or "") if map_path else {}
        if not previous and json_path:
            previous = read_deny_json(json_path)
        out = deny_list(result, previous=previous, **kwargs)
        if out.get("error"):
            return out
        old = ""
        if map_path and os.path.exists(map_path):
            try:
                old = open(map_path, encoding="utf-8").read()
            except OSError:
                old = ""
        out["changed"] = old != out["nginx"]
        for path, payload in ((map_path, out["nginx"]), (json_path, None)):
            if not path:
                continue
            directory = os.path.dirname(os.path.abspath(path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            handle, tmp = tempfile.mkstemp(dir=directory or ".", prefix=".deny-")
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                if payload is None:
                    json.dump(out["json"], fh, indent=1, sort_keys=True)
                else:
                    fh.write(payload)
            staged.append((tmp, path))
        # map first: if it lands, the apply unit may consume a complete file
        if map_path:
            os.replace(staged[0][0], staged[0][1])
            staged.pop(0)
        if json_path and staged:
            try:
                os.replace(staged[0][0], staged[0][1])
                staged.pop(0)
            except OSError as exc:
                out["json_error"] = str(exc)
        return out
    except OSError as exc:
        for tmp, _path in staged:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return {"error": "deny list write failed: %s" % exc, "entries": [],
                "count": 0, "skipped": [], "nginx": "", "json": {},
                "changed": False}
    finally:
        for tmp, _path in staged:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        _release_lock(lock)

