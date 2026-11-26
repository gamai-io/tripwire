#!/usr/bin/env python3
"""Turn a real nginx log into a redacted corpus the tests can carry.

What is kept: timestamps (shifted to a fixed base, spacing preserved), status
codes, byte counts, method class, the *number* of distinct paths and sources, and
the user-agent class (desktop/mobile/curl/bot) that the rules actually use.

What is replaced: every address (documentation range), every path (a stable hash),
every query string, every user-agent and referer.

    python3 tools/redact_corpus.py /var/log/nginx/access.log \
        --out tests/corpus/redacted --limit 2000
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys

LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"')

BASE = 1_793_491_200          # 2026-11-01T00:00:00Z
PATH_SALT = "tripwire-corpus-v1"


def path_key(raw: str) -> str:
    return hashlib.sha256((PATH_SALT + raw).encode("utf-8")).hexdigest()[:8]


def ua_class(ua: str) -> str:
    low = ua.lower()
    if not ua or ua == "-":
        return "-"
    if "curl" in low or "wget" in low or "python-" in low or "go-http" in low:
        return "curl/8.7.1"
    if any(bot in low for bot in ("bot", "crawler", "spider")):
        return "Mozilla/5.0 (compatible; Googlebot/2.1)"
    if "android" in low or "iphone" in low or "mobile" in low:
        return "Mozilla/5.0 (Linux; Android 15) Mobile"
    return "Mozilla/5.0 (X11; Linux x86_64) Chrome/157"


def method_class(method: str) -> str:
    method = method.upper()
    return method if method in ("GET", "POST", "PUT", "DELETE", "HEAD",
                                "OPTIONS", "PATCH") else "OTHER"


def request_parts(request: str) -> tuple[str, str]:
    request = "".join(ch if ch.isprintable() else "?" for ch in request)
    parts = request.split(" ")
    if len(parts) < 2:
        return "OTHER", "/r/bad-request"
    method = method_class(parts[0])
    target = parts[1].split("?", 1)[0].split("#", 1)[0]
    target = "".join(ch if ch.isprintable() else "?" for ch in target)
    if not target.startswith("/"):
        target = "/r/non-path"
    return method, "/r/" + path_key(target)


def parse_time(text: str) -> dt.datetime:
    return dt.datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")


class Redactor:
    def __init__(self):
        self.ips: dict[str, str] = {}
        self.first: dt.datetime | None = None

    def address(self, ip: str) -> str:
        if ip in self.ips:
            return self.ips[ip]
        parts = ip.split(".")
        private = False
        try:
            octets = [int(p) for p in parts]
            private = (len(octets) != 4 or octets[0] in (10, 127)
                       or (octets[0] == 192 and octets[1] == 168)
                       or (octets[0] == 172 and 16 <= octets[1] <= 31))
        except ValueError:
            private = True
        index = len(self.ips)
        if private:
            mapped = "10.0.0.%d" % (index % 250 + 1)
        else:
            block = "203.0.113" if index % 2 == 0 else "198.51.100"
            mapped = "%s.%d" % (block, index % 250 + 1)
        self.ips[ip] = mapped
        return mapped

    def line(self, raw: str) -> str | None:
        match = LINE.match(raw.rstrip("\n"))
        if not match:
            return None
        try:
            moment = parse_time(match.group("ts"))
        except ValueError:
            return None
        if self.first is None:
            self.first = moment
        shifted = BASE + int((moment - self.first).total_seconds())
        stamp = dt.datetime.fromtimestamp(shifted, dt.timezone.utc)
        when = stamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
        method, path = request_parts(match.group("request"))
        status = match.group("status") if match.group("status").isdigit() else "400"
        size = match.group("bytes") if match.group("bytes").isdigit() else "-"
        return '%s - - [%s] "%s %s HTTP/1.1" %s %s "-" "%s"' % (
            self.address(match.group("ip")), when, method, path, status, size,
            ua_class(match.group("ua")))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=2000)
    args = ap.parse_args(argv)
    redactor = Redactor()
    kept = skipped = 0
    os.makedirs(args.out, exist_ok=True)
    out_path = os.path.join(args.out, "access.log")
    with open(args.log, encoding="utf-8", errors="replace") as source, \
            open(out_path, "w", encoding="utf-8") as target:
        for raw in source:
            if kept >= args.limit:
                break
            line = redactor.line(raw)
            if line is None:
                skipped += 1
                continue
            target.write(line + "\n")
            kept += 1
    manifest = {
        "generator": "tools/redact_corpus.py",
        "lines": kept,
        "skipped": skipped,
        "distinct_sources": len(redactor.ips),
        "base": dt.datetime.fromtimestamp(BASE, dt.timezone.utc).isoformat(),
        "note": "addresses are documentation ranges; paths are salted hashes; "
                "user agents are reduced to the four classes the rules use",
    }
    with open(os.path.join(args.out, "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    print(json.dumps(manifest, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
