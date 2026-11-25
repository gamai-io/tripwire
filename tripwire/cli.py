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
        res = detect.watch(a.log, registry, a.window, a.ledger)
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        floor = order[a.min_level]
        flagged = {ip: s for ip, s in res["sessions"].items()
                   if order.get(s["level"], 0) >= floor}
        _emit({"sources": res["sources"], "flagged": len(flagged),
               "canary_hits": len(res["canary_hits"]),
               "spec_derived_paths": len(res["spec_derived_paths"]),
               "sessions": flagged})
        return 0 if not flagged else 1

    if a.cmd == "check":
        hits = canary.match(a.token, canary.load(a.registry))
        _emit({"planted": bool(hits), "canaries": [h.get("id") for h in hits]})
        return 0 if hits else 1

    ap.print_help(sys.stderr)
    return 2
