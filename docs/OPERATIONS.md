# Running it in production

One process, one file, one exit code. This is the shape that was measured; the
numbers below are from this machine unless marked otherwise.

## The deployment that works today

Tripwire is a **one-shot CLI**, not a daemon. The window *is* the memory, so a
timer every minute over a ten-minute window gives you the same coverage as a
tail without holding state in RAM between runs.

```ini
# packaging/tripwire-watch.timer
[Timer]
OnUnitActiveSec=60s
Unit=tripwire-watch.service
```

Two units, on purpose. `packaging/tripwire-watch.service` is unprivileged
(`User=tripwire`, `SupplementaryGroups=adm` so the nginx log is readable,
`ProtectSystem=strict`, `SuccessExitStatus=0 1`) and writes the list to
`/var/lib/tripwire/deny.conf`. It never touches nginx.
`packaging/tripwire-apply.path` watches that file and starts
`packaging/tripwire-apply.service` (root, oneshot), which runs
`tripwire-apply-nginx.sh`: it copies the list into place, runs `nginx -t`, and
restores the previous file if nginx rejects it — so a bad list does not survive.

```bash
install -m 0755 packaging/tripwire-apply-nginx.sh /usr/local/sbin/
cp packaging/tripwire-watch.* packaging/tripwire-apply.* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tripwire-watch.timer tripwire-apply.path
journalctl -u tripwire-watch -n 20
```

`--state` is passed, so a repeat is written once per hour (default TTL) instead of
every minute. The unit also passes `--baseline`, `--exceptions` and
`--deny-json`.

Ledger rotation: `packaging/tripwire-logrotate` (weekly, 52 copies, compressed).
`--state` keeps a cron from repeating the same alert every minute.

**Do not rotate the ledger with `copytruncate`.** The hash chain is continuous; a
truncated file restarts at `GENESIS` and the two halves no longer verify as one
chain. Rotate by renaming (`create` mode, as the shipped logrotate file does) and
ship each segment separately.

## Exit codes are part of the interface

| code | meaning | what a monitoring system should do |
|---|---|---|
| 0 | analysed, nothing at or above `--min-level` | nothing |
| 1 | analysed, findings at or above `--min-level` | page someone |
| 2 | usage error | fix the unit file |
| 3 | **could not analyse** (missing/unreadable log, no parsable rows, or every row outside the window / future-dated) | page the operator: a detector that cannot read its input is not "clean" |
| 4 | **refused** (explicit canary registry missing or unreadable, deny cap exceeded, deny list not writable) | page: a silent detector is the failure mode that matters |

3 and 4 exist because the earlier version returned 0 for a log it never read and
reported `planted: false` for a corrupt canary registry. Both are now tests.

## What the reader refuses

A log is input, not a fact. Lines are read with a 1 MiB cap (`logread.MAX_LINE`):
a longer line is drained in chunks and counted as `oversize` instead of being held
in memory, so one malformed 40 MB line cannot cost 40 MB of RSS. JSONL is parsed
with duplicate keys **rejected** (a second `"ip"` is a tamper, not a last-wins
update), and a timestamp outside 2000-01-01 .. now+10 years is skipped. Combined
log fields are validated before `calendar.timegm`, so hour 99 is refused instead
of silently rolling the event two days forward. Every refused line lands in
`skipped_lines`, with `oversize_lines`, `duplicate_keys` and `bad_timestamps`
broken out in the JSON output.

`--trusted-proxy` refuses a prefix shorter than /16 (IPv4) or /48 (IPv6) with
exit 2 unless `--allow-wide-proxy` is passed: `10.0.0.1/8` trusts everyone in
`10.0.0.0/8`, including the attacker's `X-Forwarded-For`.

## Deny list lifecycle

`--deny-map` merges with what is already on disk:

- entries from an earlier run that have not expired are **kept** — a quiet minute
  no longer lifts a block that should stand;
- expired entries are dropped;
- the file is replaced with `os.replace`, so nginx never reads a half-written
  list;
- `--deny-max` (default 1000) **refuses** to write a larger list instead of
  quietly feeding nginx something that costs throughput (measured: 50k deny rules
  cut nginx from 3,397 to 1,508 req/s);
- existing entries are re-validated on every run: a private address or a value
  that does not parse is dropped, and an active `--exceptions` entry lifts a
  block that is already on disk;
- `--reload-cmd` runs only when the payload actually changed, and its exit code
  and stderr are in the JSON output.

What it does **not** do: apply the list. That is your edge — nginx `include`,
Envoy, Cloudflare, or fail2ban. A tool that silently rewrites firewall state is a
tool that can take a bank offline at 03:00.

## Measured performance

After the linear-window fixes (0.3.0 + `gama-mandate` 0.44):

| workload | parse | analyse | peak RSS |
|---|---|---|---|
| 20,000 lines, 1 address, 1 path | 0.10 s | **0.27 s** | 49 MB |
| 100,000 lines, 1 address, 1 path, **one** key | 0.11 s | **1.20 s** | 1.5 KB/row |
| 300,000 lines, 10k sources, 300 paths | 1.6 s | **5.6 s** | 303 MB |

Before the fix, the same 100k single-key case took **658 s** and returned zero
findings (the old `key_probing` rescanned the window per row). The ops review
measured 0.2.0 at 1M lines: 89.7 s and 1.47 GB, with 62–80% of the time in that
one rule.

**Streaming.** With a window smaller than the file (`--stream`), memory is bounded
by the sources inside the window, not by the file. Measured here on 2026-11-26:
100,000 rows / 200 sources inside a 600 s window peaked at **146 MB and 2.46 s**;
500,000 unique sources are the worst case because every one is a live session, so
size the box for *sources in the window* (roughly 1.5 KB each), not for the file.
Use `--stream` when the file spans more than the window; with `--window` covering
the whole file there is nothing to trim and the two modes converge.

**Sizing.** Roughly 1–1.5 KB of RAM per row, 12k lines/s best case. A bank branch
average of 579 lines/s is fine for a one-minute cadence; a 50M-lines/day firehose
is not — that needs a streaming aggregate, which is not built. Say so in the
proposal rather than discovering it in the pilot.

## What is deliberately missing

- **No tail mode.** Re-run on a timer; `--state` handles repeats.
- **No inline blocking.** Deliberate: one wrong entry blocks a carrier.
- **Baselines are per path template, not per endpoint version.** A rename of the
  path (`/v1/x` → `/v2/x`) starts a new cold baseline.
- **No multi-tenant separation.** One process, one log, one ledger.
- **Streaming is chunked, not incremental.** It bounds memory by the window, but a
  rule that needs two events in different chunks can be missed; the window is the
  unit of correctness.
