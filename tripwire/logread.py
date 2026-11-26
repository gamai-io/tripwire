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
import time

# A line longer than this is a collector bug or a deliberate flood, not a log
# row. Reading it whole would let one 40 MB line cost 40 MB of RSS, so it is
# drained in chunks and counted instead.
MAX_LINE = 1024 * 1024
# An epoch outside this range is not a timestamp we can reason about. The upper
# bound is relative to the clock so a long-lived pipeline does not age out.
EPOCH_FLOOR = 946_684_800              # 2000-01-01T00:00:00Z
EPOCH_CEILING = 10 * 365 * 86_400      # ten years ahead of now

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"')

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


def _parse_time(text: str) -> float | None:
    """25/Nov/2026:00:00:22 +0100 -> epoch seconds (no locale dependency).

    The fields are validated here, not left to `calendar.timegm`, which silently
    normalises ``25/Nov/2026:99:00:22`` into two days later. A clock that is off
    by four days must not move an event out of its window.
    """
    try:
        date_part, zone = text.split(" ", 1)
        day, month, rest = date_part.split("/")
        year, hour, minute, second = rest.split(":")
        day, year = int(day), int(year)
        hour, minute, second = int(hour), int(minute), int(second)
        zone_hour, zone_minute = int(zone[1:3]), int(zone[3:5])
        month_number = _MONTHS[month]
        if not (1970 <= year <= 2100
                and 1 <= day <= calendar.monthrange(year, month_number)[1]
                and 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 60
                and zone_hour <= 23 and zone_minute <= 59):
            return None
        sign = -1 if zone.startswith("-") else 1
        offset = zone_hour * 3600 + zone_minute * 60
        stamp = calendar.timegm((year, month_number, day,
                                 hour, minute, second, 0, 0, 0))
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


def _status(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class _DuplicateKey(ValueError):
    """A JSON object named the same field twice: last-wins would hide a tamper."""


def _pairs_without_duplicates(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKey(key)
        seen.add(key)
    return dict(pairs)


def sane_epoch(value) -> bool:
    """Can this value be a timestamp we can place in a window?

    `detect` would otherwise treat an epoch of 1 or 9e18 as a real event and
    either drop it silently or let it blind the run.
    """
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return False
    if ts != ts:                      # NaN
        return False
    return EPOCH_FLOOR <= ts <= time.time() + EPOCH_CEILING


def _parse_line(line: str, fmt: str) -> tuple[dict | None, str]:
    """One logical line -> (row, reason-it-was-skipped)."""
    if fmt == "combined":
        row = parse_combined(line)
        return row, "" if row else "unparsed"
    try:
        row = json.loads(line, object_pairs_hook=_pairs_without_duplicates)
    except _DuplicateKey:
        return None, "duplicate_keys"
    except ValueError:
        return None, "bad_json"
    if not isinstance(row, dict):
        return None, "not_object"
    if not sane_epoch(row.get("ts")):
        return None, "bad_timestamps"
    if not row.get("ua_platform") and row.get("ua"):
        row["ua_platform"] = _platform(str(row["ua"]))
    return row, ""


def _empty_stats(fmt: str) -> dict:
    return {"lines": 0, "skipped": 0, "format": fmt, "oversize": 0,
            "bad_json": 0, "bad_timestamps": 0, "duplicate_keys": 0}


def _read_lines(fh):
    """Yield physical lines, holding at most MAX_LINE bytes of any one of them.

    An oversize line is drained and yielded as None so the caller can count it;
    reading it whole is exactly the 40 MB RSS case this exists to avoid.
    """
    while True:
        chunk = fh.readline(MAX_LINE + 1)
        if not chunk:
            return
        if chunk.endswith("\n") and len(chunk) <= MAX_LINE + 1:
            yield chunk
            continue
        if len(chunk) <= MAX_LINE:          # trailing line with no newline
            yield chunk
            return
        while not chunk.endswith("\n"):     # drain the rest without keeping it
            chunk = fh.readline(MAX_LINE)
            if not chunk:
                break
        yield None


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
        "status": _status(match.group("status")),
        "auth": "none" if user in ("-", "") else user,
        "referer": "" if referer == "-" else referer,
        "ua_platform": _platform(ua),
        "bytes": int(match.group("bytes")) if match.group("bytes") != "-" else 0,
    }


def guess_format(path: str) -> str:
    seen = 0
    with _open(path) as fh:
        for raw in _read_lines(fh):
            seen += 1
            if seen > 20:
                break
            if raw is None:
                continue
            line = raw.strip()
            if not line:
                continue
            if line.lstrip().startswith("{"):
                return "jsonl"
            if COMBINED.match(line):
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
    stats = _empty_stats(fmt)
    with _open(path) as fh:
        for raw in _read_lines(fh):
            if raw is None:
                stats["lines"] += 1
                stats["skipped"] += 1
                stats["oversize"] += 1
                continue
            line = raw.strip()
            if not line:
                continue
            stats["lines"] += 1
            row, reason = _parse_line(line, fmt)
            if row is None:
                stats["skipped"] += 1
                if reason in stats:
                    stats[reason] += 1
                continue
            rows.append(resolve_client(row, trusted))
    return rows, stats


def load(path: str, fmt: str = "auto", trusted: list | None = None) -> list[dict]:
    return load_stats(path, fmt, trusted)[0]


def iter_rows(path: str, fmt: str = "auto", trusted: list | None = None,
              stats: dict | None = None):
    """Yield rows one at a time, so a 50M-line file never lands in memory at once.

    `stats` (optional dict) receives `lines`, `skipped` and the reason counters,
    including `oversize` for lines longer than MAX_LINE.
    """
    fmt = guess_format(path) if fmt in ("", "auto") else fmt
    with _open(path) as fh:
        for raw in _read_lines(fh):
            if raw is None:
                if stats is not None:
                    stats["lines"] = stats.get("lines", 0) + 1
                    stats["skipped"] = stats.get("skipped", 0) + 1
                    stats["oversize"] = stats.get("oversize", 0) + 1
                continue
            line = raw.strip()
            if not line:
                continue
            if stats is not None:
                stats["lines"] = stats.get("lines", 0) + 1
            row, reason = _parse_line(line, fmt)
            if row is None:
                if stats is not None:
                    stats["skipped"] = stats.get("skipped", 0) + 1
                    if reason in stats:
                        stats[reason] = stats.get(reason, 0) + 1
                continue
            yield resolve_client(row, trusted)


def count_lines(path: str) -> tuple[int, int]:
    """Total lines and unparsable lines, without keeping anything."""
    total = good = 0
    fmt = guess_format(path)
    with _open(path) as fh:
        for raw in _read_lines(fh):
            if raw is not None and not raw.strip():
                continue
            total += 1
            if raw is None:              # oversize is unparsable by definition
                continue
            if _parse_line(raw.strip(), fmt)[0] is not None:
                good += 1
    return total, total - good
