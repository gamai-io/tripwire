"""Read access logs: our JSONL, nginx/Apache combined, or auto-detected.

Every detector that only accepts a bespoke format is a detector nobody turns on.
`nginx` and `apache` both default to the combined log format, so that is the
second reader; the JSONL schema stays the richer one (it can carry the auth
value, which is what the key-probing rule needs).
"""
from __future__ import annotations

import calendar
import gzip
import ipaddress
import json
import re

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"')

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


def _parse_time(text: str) -> float | None:
    """25/Nov/2026:00:00:22 +0100 -> epoch seconds (no locale dependency)."""
    try:
        date_part, zone = text.split(" ", 1)
        day, month, rest = date_part.split("/")
        year, hour, minute, second = rest.split(":")
        sign = -1 if zone.startswith("-") else 1
        offset = int(zone[1:3]) * 3600 + int(zone[3:5]) * 60
        stamp = calendar.timegm((int(year), _MONTHS[month], int(day),
                                 int(hour), int(minute), int(second), 0, 0, 0))
        return stamp - sign * offset
    except (ValueError, KeyError, IndexError):
        return None


def _platform(ua: str) -> str:
    low = (ua or "").lower()
    if any(token in low for token in ("mobile", "android", "iphone", "ipad")):
        return "mobile"
    if low in ("", "-"):
        return ""
    return "desktop"


def parse_combined(line: str) -> dict | None:
    match = COMBINED.match(line.strip())
    if not match:
        return None
    ts = _parse_time(match.group("ts"))
    if ts is None:
        return None
    request = match.group("request")
    parts = request.split()
    if len(parts) >= 2:
        method, path = parts[0], parts[1]
    elif parts:
        method, path = parts[0], ""
    else:
        method, path = "", ""
    user = match.group("user")
    ua = match.group("ua")
    referer = match.group("referer")
    return {
        "ts": ts, "ip": match.group("ip"), "ua": "" if ua == "-" else ua,
        "method": method or "GET", "path": path or "/",
        "status": int(match.group("status")),
        "auth": "none" if user in ("-", "") else user,
        "referer": "" if referer == "-" else referer,
        "ua_platform": _platform(ua),
        "bytes": int(match.group("bytes")) if match.group("bytes") != "-" else 0,
    }


def guess_format(path: str) -> str:
    with _open(path) as fh:
        for _ in range(20):
            line = fh.readline()
            if not line.strip():
                continue
            if line.lstrip().startswith("{"):
                return "jsonl"
            if COMBINED.match(line.strip()):
                return "combined"
    return "jsonl"


def _in_trusted(ip: str, trusted: list) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for item in trusted:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def resolve_client(row: dict, trusted: list | None = None) -> dict:
    """Trust `X-Forwarded-For` only from an address you named.

    Behind a CDN or a load balancer every request arrives from the proxy, so the
    peer address is useless. But if anyone may set the header, an attacker picks
    someone else's address and gets that address blocked — the header is a
    weapon unless the proxy is pinned. Unlisted peers keep their own address and
    the spoof is visible in `xff_ignored`.
    """
    trusted = trusted or []
    raw = str(row.get("xff") or "").strip()
    if not raw:
        return row
    if not _in_trusted(str(row.get("ip") or ""), trusted):
        row = dict(row)
        row["xff_ignored"] = raw[:200]
        return row
    hops = [part.strip() for part in raw.split(",") if part.strip()]
    client = ""
    for hop in reversed(hops):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            continue
        if not _in_trusted(hop, trusted):
            client = hop
            break
    if client:
        row = dict(row)
        row["peer"] = row.get("ip")
        row["ip"] = client
    return row


def _open(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def load_stats(path: str, fmt: str = "auto",
               trusted: list | None = None) -> tuple[list[dict], dict]:
    fmt = guess_format(path) if fmt in ("", "auto") else fmt
    rows: list[dict] = []
    stats = {"lines": 0, "skipped": 0, "format": fmt}
    with _open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            stats["lines"] += 1
            if fmt == "combined":
                row = parse_combined(line)
            else:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(row, dict):
                    continue
                if not row.get("ua_platform") and row.get("ua"):
                    row["ua_platform"] = _platform(str(row["ua"]))
            if row:
                rows.append(resolve_client(row, trusted))
            else:
                stats["skipped"] += 1
    return rows, stats


def load(path: str, fmt: str = "auto", trusted: list | None = None) -> list[dict]:
    return load_stats(path, fmt, trusted)[0]


def iter_rows(path: str, fmt: str = "auto", trusted: list | None = None):
    """Yield rows one at a time, so a 50M-line file never lands in memory at once."""
    fmt = guess_format(path) if fmt in ("", "auto") else fmt
    with _open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if fmt == "combined":
                row = parse_combined(line)
            else:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(row, dict):
                    continue
                if not row.get("ua_platform") and row.get("ua"):
                    row["ua_platform"] = _platform(str(row["ua"]))
            if row:
                yield resolve_client(row, trusted)


def count_lines(path: str) -> tuple[int, int]:
    """Total lines and unparsable lines, without keeping anything."""
    total = good = 0
    fmt = guess_format(path)
    with _open(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            total += 1
            if fmt == "combined":
                good += 1 if parse_combined(line) else 0
            else:
                try:
                    good += 1 if isinstance(json.loads(line), dict) else 0
                except ValueError:
                    pass
    return total, total - good
