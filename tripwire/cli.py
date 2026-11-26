"""Command line: plant canaries, then watch an access log."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

from . import canary, detect


def _emit(obj) -> None:
    print(json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=True))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tripwire",
                                 description="Detect an inbound agent by behaviour, not blocklists.")
    sub = ap.add_subparsers(dest="cmd")

    p_gen = sub.add_parser("canary", help="plant, list or revoke canary keys")
    p_gen.add_argument("action", choices=("generate", "list", "revoke"))
    p_gen.add_argument("--count", type=int, default=3)
    p_gen.add_argument("--note", default="")
    p_gen.add_argument("--id", default=None, help="canary id (revoke)")
    p_gen.add_argument("--registry", default="canaries.json")
    p_gen.add_argument("--plant-dir", dest="plant_dir", default="",
                       help="also write decoy documents containing the tokens")

    p_watch = sub.add_parser("watch", help="score an access log")
    p_watch.add_argument("--log", required=True)
    p_watch.add_argument("--registry", default=None,
                         help="canary registry; omit to run without canaries")
    p_watch.add_argument("--window", type=int, default=detect.agentwatch.WINDOW)
    p_watch.add_argument("--ledger", default=None,
                         help="append control/alert records to this mandate ledger")
    p_watch.add_argument("--min-level", dest="min_level",
                         choices=("low", "medium", "high", "critical"), default="medium")
    p_watch.add_argument("--format", choices=("auto", "jsonl", "combined"), default="auto",
                         help="auto-detect, our JSONL, or nginx/Apache combined")
    p_watch.add_argument("--deny-map", dest="deny_map", default=None,
                         help="write an nginx deny list for flagged sources")
    p_watch.add_argument("--deny-json", dest="deny_json", default=None,
                         help="write the same list as JSON, with expiry per entry")
    p_watch.add_argument("--deny-ttl", dest="deny_ttl", type=int, default=3600)
    p_watch.add_argument("--now", default="file",
                         help="'file' (default: newest row), 'wall', or an epoch")
    p_watch.add_argument("--stream", action="store_true",
                         help="score a file too large for memory: keep only the window")
    p_watch.add_argument("--chunk", type=int, default=200000,
                         help="rows per scoring pass in --stream mode")
    p_watch.add_argument("--baseline", default=None,
                         help="JSON file with per-path history; enables distributed-scan "
                              "detection and is updated after a clean run")
    p_watch.add_argument("--baseline-factor", dest="baseline_factor", type=float,
                         default=3.0)
    p_watch.add_argument("--baseline-floor", dest="baseline_floor", type=int, default=10)
    p_watch.add_argument("--no-baseline-update", dest="baseline_update",
                         action="store_false", default=True)
    p_watch.add_argument("--state", default=None,
                         help="JSON file remembering alerts, so a cron does not repeat them")
    p_watch.add_argument("--state-ttl", dest="state_ttl", type=int, default=3600)
    p_watch.add_argument("--deny-max", dest="deny_max", type=int, default=1000,
                         help="refuse to write more entries than this (a huge list "
                              "costs nginx throughput and hides a bug)")
    p_watch.add_argument("--reload-cmd", dest="reload_cmd", default=None,
                         help="command to run after the list changes, e.g. "
                              "'nginx -t && nginx -s reload'")
    p_watch.add_argument("--deny-unsafe", dest="deny_unsafe", action="store_true",
                         help="also deny on volume evidence alone (CDN/NAT risk)")
    p_watch.add_argument("--trusted-proxy", dest="trusted_proxy", action="append",
                         default=None,
                         help="CIDR of a proxy whose X-Forwarded-For is trusted "
                              "(repeatable; unlisted peers keep their own address)")
    p_watch.add_argument("--exceptions", default=None,
                         help="JSON whitelist with ip, until and approver")
    p_watch.add_argument("--ignore", action="append", default=None,
                         help="address never to deny (repeatable, e.g. your scanner)")

    p_check = sub.add_parser("check", help="is this string a planted canary?")
    p_check.add_argument("--token", required=True)
    p_check.add_argument("--registry", default="canaries.json")

    a = ap.parse_args(argv)

    if a.cmd == "canary":
        if a.action == "generate":
            res = canary.generate(a.count, a.note, a.registry,
                                  plant_dir=a.plant_dir)
            _emit({"registry": res["path"], "count": res["count"],
                   "tokens": res["tokens"], "planted": res.get("planted") or [],
                   "note": "shown once: only sha256 is stored, revoke by id"})
            return 0
        if a.action == "list":
            data = canary.load(a.registry)
            _emit({"count": len([c for c in data.get("canaries", []) if not c.get("revoked")]),
                   "canaries": [{k: c.get(k) for k in ("id", "note", "created", "revoked")}
                                for c in data.get("canaries", [])]})
            return 0
        if not a.id:
            _emit({"error": "usage", "message": "canary revoke --id ID"})
            return 2
        _emit(canary.revoke(a.id, a.registry))
        return 0

    if a.cmd == "watch":
        try:
            registry = canary.load(a.registry, strict=True) if a.registry else {"canaries": []}
        except canary.RegistryError as exc:
            _emit({"error": "RegistryError",
                   "message": "refusing to run without a usable canary registry: %s" % exc})
            return 4
        now = None
        if a.now == "wall":
            import time as _time
            now = _time.time()
        elif a.now not in ("file", ""):
            try:
                now = float(a.now)
            except ValueError:
                _emit({"error": "Usage", "message": "--now takes 'file', 'wall' or an epoch"})
                return 2
        common = dict(window=a.window, ledger=a.ledger, fmt=a.format, now=now,
                      trusted=a.trusted_proxy,
                      baseline_path=a.baseline or "",
                      baseline_factor=a.baseline_factor,
                      baseline_floor=a.baseline_floor,
                      baseline_update=a.baseline_update)
        try:
            if a.stream:
                res = detect.watch_stream(a.log, registry, chunk=a.chunk, **common)
            else:
                res = detect.watch(a.log, registry, **common)
        except OSError as exc:
            _emit({"error": "Unreadable", "message": str(exc)})
            return 3
        if res.get("empty"):
            _emit({"sources": 0, "flagged": 0, "rows": 0,
                   "skipped_lines": res.get("skipped_lines", 0),
                   "error": "no rows",
                   "message": "the file has no parsable lines for format %r"
                              % res.get("log_format")})
            return 3
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        floor = order[a.min_level]
        flagged = {ip: s for ip, s in res["sessions"].items()
                   if order.get(s["level"], 0) >= floor}
        deny = detect.write_deny_files(res, a.deny_map, a.deny_json,
                                       min_level=a.min_level, ttl_s=a.deny_ttl,
                                       ignore=set(a.ignore or ()),
                                       allow_volume=a.deny_unsafe, cap=a.deny_max)
        if deny.get("error"):
            _emit({"error": "DenyRefused", "message": deny["error"],
                   "sessions": flagged}, None)
            return 4
        reload_status = None
        if a.reload_cmd and deny["count"]:
            done = subprocess.run(a.reload_cmd, shell=True, capture_output=True, text=True)
            reload_status = {"command": a.reload_cmd, "exit": done.returncode,
                             "stderr": done.stderr.strip()[:200]}
        _emit({"sources": res["sources"], "rows": res.get("rows"),
               "skipped_lines": res.get("skipped_lines", 0),
               "flagged": len(flagged),
               "canary_hits": len(res["canary_hits"]),
               "spec_derived_paths": len(res["spec_derived_paths"]),
               "path_anomalies": res.get("path_anomalies", []),
               "deny_entries": deny["count"],
               "new_alerts": res.get("new_alerts", len(flagged)),
               "deny_skipped": len(deny["skipped"]),
               "reload": reload_status,
               "sessions": flagged})
        return 0 if not flagged else 1

    if a.cmd == "check":
        try:
            hits = canary.match(a.token, canary.load(a.registry, strict=True))
        except canary.RegistryError as exc:
            _emit({"error": "RegistryError", "message": str(exc)})
            return 4
        _emit({"planted": bool(hits), "canaries": [h.get("id") for h in hits]})
        return 0 if hits else 1

    ap.print_help(sys.stderr)
    return 2
