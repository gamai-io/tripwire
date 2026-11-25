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
import tempfile
import time
import urllib.parse
from collections import defaultdict

from mandate import agentwatch
from mandate.core import append_receipt

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


def _failed_here(rows: list[dict]) -> bool:
    return any(int(r.get("status") or 0) in FAILED for r in rows)


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
    base = agentwatch.analyse(rows, window=window, now=now)
    by_ip = defaultdict(list)
    for row in rows:
        by_ip[str(row.get("ip") or "?")].append(row)

    canary_hits = []
    for row in rows:
        text = " ".join(str(row.get(k) or "") for k in
                        ("path", "ua", "referer", "query", "body", "auth"))
        text = urllib.parse.unquote(text)      # query strings arrive percent-encoded
        for hit in canary_mod.match(text, registry or {}):
            canary_hits.append({"ip": row.get("ip"), "ts": row.get("ts"),
                                "path": row.get("path"), "canary": hit.get("id")})

    for item in spec_derived_paths(rows):
        session = base["sessions"].get(item["ip"])
        if session is not None:
            session["findings"].append({
                "rule": "spec_derived_novel_path", "points": 3,
                "detail": "first request to %s %.1fs after an API document"
                          % (item["path"], item["seconds_after_doc"])})
            session["points"] += 3
            session["level"] = _level(session["points"])

    for item in auth_failure_streak(rows):
        session = base["sessions"].get(item["ip"])
        if session is not None:
            session["findings"].append({
                "rule": "auth_failure_streak", "points": 4,
                "detail": "%d rejected credentials on %s in %.0fs"
                          % (item["attempts"], item["path"], max(item["seconds"], 1))})
            session["points"] += 4
            session["level"] = _level(session["points"])

    for item in path_burst(rows):
        session = base["sessions"].get(item["ip"])
        if session is not None:
            session["findings"].append({
                "rule": "path_burst", "points": 3,
                "detail": "%d distinct paths in %ds" % (item["paths"], item["seconds"])})
            session["points"] += 3
            session["level"] = _level(session["points"])

    for item in wide_probe(rows):
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
            "failures": sum(1 for r in items if int(r.get("status") or 0) in FAILED),
            "user_agents": len({str(r.get("ua") or "") for r in items}),
        }

    return {"window_s": window, "sources": base["sources"], "evidence": evidence,
            "flagged": sum(1 for s in base["sessions"].values() if s["level"] != "low"),
            "canary_hits": canary_hits, "spec_derived_paths": spec_derived_paths(rows),
            "auth_failure_streaks": auth_failure_streak(rows),
            "sessions": base["sessions"]}


def watch(log_path: str, registry: dict | None = None, window: int = 600,
          ledger: str | None = None, fmt: str = "auto",
          now: float | None = None, trusted: list | None = None) -> dict:
    """Score a file.

    `now` defaults to the newest row in the file, so a log written yesterday is
    still analysed instead of silently producing "0 sources, 0 flagged". Pass
    `now=time.time()` for live tailing.
    """
    rows = logread.load(log_path, fmt, trusted)
    if now is None and rows:
        now = max(float(r.get("ts") or 0) for r in rows) + 1
    result = analyse(rows, registry, window, now=now)
    result["rows"] = len(rows)
    result["empty"] = not rows
    result["now"] = now
    if ledger:
        alerts = {ip: s for ip, s in result["sessions"].items() if s["level"] != "low"}
        if alerts:
            append_receipt(ledger, {"v": 1, "type": "control", "action": "alert",
                                    "actor": "tripwire",
                                    "reason": "inbound agent behaviour",
                                    "ts": time.time(), "log": log_path,
                                    "canary_hits": result["canary_hits"],
                                    "findings": alerts})
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
    """
    by_ip = defaultdict(list)
    for row in rows:
        ua = str(row.get("ua") or "").lower()
        if any(bot in ua for bot in GOOD_BOTS):
            continue
        by_ip[str(row.get("ip") or "?")].append((float(row.get("ts") or 0),
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


IDENTITY_RULES = {"canary_used", "key_probing", "auth_failure_streak"}
BEHAVIOUR_RULES = {"ua_flip", "tool_switch", "docs_link_follow",
                   "spec_derived_novel_path", "read_after_submit"}


def deny_evidence(session: dict, evidence: dict | None) -> tuple[bool, str]:
    """Blocking an address is a bigger decision than alerting on it.

    Volume rules (`velocity`, `wide_probe`, `low_and_slow_scan`) fire on shared
    egress — a CDN, a corporate NAT, a hospital with one line — so they can alert
    but not deny. Denial needs identity evidence (canary, probed or rejected
    credentials), two independent behaviours, or one behaviour plus real failures.
    """
    rules = {f["rule"] for f in session.get("findings") or [] if not f.get("suppressed")}
    if "canary_used" in rules:
        return True, "canary"
    if rules & IDENTITY_RULES:
        return True, "identity evidence: %s" % ",".join(sorted(rules & IDENTITY_RULES))
    behaviours = rules & BEHAVIOUR_RULES
    failures = int((evidence or {}).get("failures") or 0)
    if len(behaviours) >= 2:
        return True, "two behaviours: %s" % ",".join(sorted(behaviours))
    if behaviours and failures >= 5:
        return True, "behaviour + %d failed requests" % failures
    return False, "volume evidence only (%s)" % (",".join(sorted(rules)) or "none")


def apply_state(result: dict, state_path: str, ttl_s: int = 3600,
                now: float | None = None) -> dict:
    """Return only what is new or worse since the last run, and remember it.

    A cron that re-runs every minute would otherwise re-alert on the same address
    until the window rolls over. State is a small JSON file; it is pruned on every
    write, so it cannot grow without bound.
    """
    moment = time.time() if now is None else now
    state = {"version": 1, "alerts": {}}
    if os.path.exists(state_path):
        try:
            state = json.load(open(state_path, encoding="utf-8"))
        except ValueError:
            state = {"version": 1, "alerts": {}}
    alerts = state.setdefault("alerts", {})
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    new = 0
    for ip, session in result["sessions"].items():
        if session["level"] == "low":
            continue
        previous = alerts.get(ip)
        expired = not previous or float(previous.get("expires") or 0) <= moment
        worse = previous and order.get(session["level"], 0) > order.get(
            previous.get("level"), 0)
        if expired or worse:
            new += 1
            session["is_new"] = True
        else:
            session["is_new"] = False
            session["repeat"] = True
        alerts[ip] = {"level": session["level"], "points": session["points"],
                      "first_seen": (previous or {}).get("first_seen", int(moment)),
                      "expires": int(moment + ttl_s)}
    alerts = {ip: item for ip, item in alerts.items()
              if float(item.get("expires") or 0) > moment}
    state["alerts"] = alerts
    directory = os.path.dirname(os.path.abspath(state_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    handle, tmp = tempfile.mkstemp(dir=directory or ".", prefix=".state-")
    with os.fdopen(handle, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(tmp, state_path)
    result["new_alerts"] = new
    return result


def deny_list(result: dict, min_level: str = "medium", now: float | None = None,
              ttl_s: int = 3600, ignore: set[str] | None = None,
              allow_volume: bool = False) -> dict:
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
    lines = ["# tripwire deny list, generated %s, ttl %ds"
             % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(moment)), ttl_s)]
    for entry in entries:
        lines.append("# %s %s points=%d expires=%d rules=%s reason=%s"
                     % (entry["ip"], entry["level"], entry["points"], entry["expires"],
                        ",".join(entry["rules"]), entry["reason"]))
        lines.append("deny %s;" % entry["ip"])
    for item in skipped:
        lines.append("# skipped %s (%s)" % (item["ip"], item["why"]))
    return {"entries": entries, "count": len(entries), "skipped": skipped,
            "nginx": "\n".join(lines) + "\n",
            "json": {"generated": int(moment), "ttl_s": ttl_s, "deny": entries}}
