"""Command line: plant canaries, then watch an access log."""
from __future__ import annotations

import argparse
import json
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

    p_watch = sub.add_parser("watch", help="score an access log")
    p_watch.add_argument("--log", required=True)
    p_watch.add_argument("--registry", default="canaries.json")
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
    p_watch.add_argument("--deny-unsafe", dest="deny_unsafe", action="store_true",
                         help="also deny on volume evidence alone (CDN/NAT risk)")
    p_watch.add_argument("--trusted-proxy", dest="trusted_proxy", action="append",
                         default=None,
                         help="CIDR of a proxy whose X-Forwarded-For is trusted "
                              "(repeatable; unlisted peers keep their own address)")
    p_watch.add_argument("--ignore", action="append", default=None,
                         help="address never to deny (repeatable, e.g. your scanner)")

    p_check = sub.add_parser("check", help="is this string a planted canary?")
    p_check.add_argument("--token", required=True)
    p_check.add_argument("--registry", default="canaries.json")

    a = ap.parse_args(argv)

    if a.cmd == "canary":
        if a.action == "generate":
            res = canary.generate(a.count, a.note, a.registry)
            _emit({"registry": res["path"], "count": res["count"],
                   "tokens": res["tokens"],
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
        registry = canary.load(a.registry) if a.registry else {"canaries": []}
        now = None
        if a.now == "wall":
            import time as _time
            now = _time.time()
        elif a.now not in ("file", ""):
            try:
                now = float(a.now)
            except ValueError:
                _emit({"error": "Usage", "message": "--now takes 'file', 'wall' or an epoch"}, None)
                return 2
        res = detect.watch(a.log, registry, a.window, a.ledger, a.format, now=now,
                           trusted=a.trusted_proxy)
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        floor = order[a.min_level]
        flagged = {ip: s for ip, s in res["sessions"].items()
                   if order.get(s["level"], 0) >= floor}
        deny = detect.deny_list(res, a.min_level, ttl_s=a.deny_ttl,
                                ignore=set(a.ignore or ()),
                                allow_volume=a.deny_unsafe)
        for path, payload in ((a.deny_map, deny["nginx"]), (a.deny_json, None)):
            if not path:
                continue
            with open(path, "w", encoding="utf-8") as fh:
                if payload is None:
                    json.dump(deny["json"], fh, indent=1, sort_keys=True)
                else:
                    fh.write(payload)
        if res.get("empty"):
            _emit({"sources": 0, "flagged": 0, "rows": 0,
                   "error": "no rows", "message": "the file has no parsable lines"}, None)
            return 3
        _emit({"sources": res["sources"], "rows": res.get("rows"), "flagged": len(flagged),
               "canary_hits": len(res["canary_hits"]),
               "spec_derived_paths": len(res["spec_derived_paths"]),
               "deny_entries": deny["count"],
               "deny_skipped": len(deny["skipped"]),
               "sessions": flagged})
        return 0 if not flagged else 1

    if a.cmd == "check":
        hits = canary.match(a.token, canary.load(a.registry))
        _emit({"planted": bool(hits), "canaries": [h.get("id") for h in hits]})
        return 0 if hits else 1

    ap.print_help(sys.stderr)
    return 2
