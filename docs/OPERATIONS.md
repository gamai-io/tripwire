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

`packaging/tripwire-watch.service` is a complete unit: unprivileged user,
`StateDirectory`, `ProtectSystem=strict`, `SuccessExitStatus=0 1`, and
`--reload-cmd "nginx -t && nginx -s reload"` so a bad list never reaches nginx.

```bash
cp packaging/tripwire-watch.* /etc/systemd/system/
systemctl enable --now tripwire-watch.timer
journalctl -u tripwire-watch -n 20
```

Ledger rotation: `packaging/tripwire-logrotate` (weekly, 52 copies, compressed).
`--state` keeps a cron from repeating the same alert every minute.

## Exit codes are part of the interface

| code | meaning | what a monitoring system should do |
|---|---|---|
| 0 | analysed, nothing at or above `--min-level` | nothing |
| 1 | analysed, findings at or above `--min-level` | page someone |
| 2 | usage error | fix the unit file |
| 3 | **could not analyse** (missing/unreadable log, no parsable rows) | page the operator: a detector that cannot read its input is not "clean" |
| 4 | **refused** (canary registry unreadable, deny cap exceeded) | page: a silent detector is the failure mode that matters |

3 and 4 exist because the earlier version returned 0 for a log it never read and
reported `planted: false` for a corrupt canary registry. Both are now tests.

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
- `--reload-cmd` runs only after a successful write, and its exit code and stderr
  are in the JSON output.

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
by the rows inside the window: on 500k lines from 200 addresses, window 600 s, the
run peaked at **34 MB and 3.6 s** instead of **492 MB and 11.9 s**. Use it when the
file spans more than the window; with `--window` covering the whole file there is
nothing to trim and the two modes converge.

**Sizing.** Roughly 1–1.5 KB of RAM per row, 12k lines/s best case. A bank branch
average of 579 lines/s is fine for a one-minute cadence; a 50M-lines/day firehose
is not — that needs a streaming aggregate, which is not built. Say so in the
proposal rather than discovering it in the pilot.

## What is deliberately missing

- **No tail mode.** Re-run on a timer; `--state` handles repeats.
- **No inline blocking.** Deliberate: one wrong entry blocks a carrier.
- **No per-path baseline.** Thresholds are global; a busy endpoint looks like a
  scanner. Next piece of work.
- **No multi-tenant separation.** One process, one log, one ledger.
- **Streaming is chunked, not incremental.** It bounds memory by the window, but a
  rule that needs two events in different chunks can be missed; the window is the
  unit of correctness.
