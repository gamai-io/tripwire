# Changelog

## 0.8.4 — 2026-11-26
- A path anomaly now obeys `--min-level` too. It is a high-severity signal, but
  it used to be written to the ledger even at `--min-level critical`; a test
  covers it. The record also states its level.

## 0.8.3 — 2026-11-26
- The claims gate now requires a test count in README (a missing anchor passed
  silently) and compares it against **passing** tests.
- `CLAIMS.md` is generated from a fresh corpus run instead of hardcoded numbers:
  it previously said 0/300, 45/60, 60/60 while the corpus had grown to 360/80.

## 0.8.2 — 2026-11-26
- **The ledger only gets what the operator asked for.** `watch --min-level` now
  filters the alerts that are written (a `--min-level high` run no longer writes
  medium findings), and `--state` suppresses repeats instead of appending a fresh
  alert every minute.
- **Exceptions that expire and are attributable**: `--exceptions FILE` with
  `{ip, until, approver, reason}`. An entry without `until` or `approver` is ignored,
  an active one is reported as `exception until … (approver)`, and the deny list
  never blocks an excepted address.
- 5 new tests; 100 total.

## 0.8.1 — 2026-11-25
- `tripwire canary generate --plant-dir DIR` writes decoy API documents that
  contain the tokens, so planting is one command instead of hand-editing a file.
  The registry still stores only hashes; the plaintext exists only in the planted
  file.
- `canary match` returns each token once, however many times it appears in a line.
- 95 tests.

## 0.8.0 — 2026-11-25
Security and correctness pass after an external review:
- **Denial now requires identity evidence** (canary, probed/rejected credentials,
  one credential across addresses with a failure ratio). Behaviours alert but no
  longer deny: `ua_flip` + `tool_switch` from one address is a shared NAT, and the
  previous rule would have blocked it.
- **Every row-based rule now honours the window.** Old 401s from hours ago no
  longer attach to today's session, and `key_across_addresses` needs a failure
  ratio, so one working key from three offices is not treated as theft.
- **Streaming no longer drops canaries**: the token is matched per row as it is
  read, not only inside a scored chunk.
- A deny list written only as JSON is merged on the next run instead of being
  wiped when the nginx map is absent.
- A future-dated line no longer blinds the run (the clock is clamped, future rows
  are excluded), and an unparsable status no longer crashes the parser.
- 93 tests.

## 0.7.1 — 2026-11-25
- Publish through OIDC trusted publishing with PEP 740 attestations (the PyPI
  publisher entry was added on 2026-11-25); the API token is no longer used.

## 0.7.0 — 2026-11-25
- `--stream` / `--chunk`: score a file too large to hold. Only the window stays in
  memory; chunks are scored and findings unioned per source with points taking the
  maximum. Measured on 500,000 lines, window 600 s: **34 MB / 3.6 s** versus
  **492 MB / 11.9 s** in batch mode.
- `logread.iter_rows` and `count_lines` so nothing needs to materialise the file.
- `rows_in_window` in the output, so the operator can see what the window held.
- Stated limit: chunk boundaries can lose a cross-chunk correlation; the window is
  the unit of correctness.
- 5 new tests; 90 total.

## 0.6.0 — 2026-11-25
- `--baseline FILE`: per-path history (EWMA of requests and distinct sources) with
  path templating, so a scan spread across many addresses is visible at the
  endpoint that is being walked. Reported per path, never per address; a window
  that trips the baseline is not folded into the history; a cold path is not an
  alarm. Anomalies are also written to the ledger (`kind=path_anomaly`).
- `--baseline-factor` (3x), `--baseline-floor` (10 sources), `--no-baseline-update`.
- 10 new tests (templating, cold start, burst after warm-up, no poisoning, atomic
  write, end-to-end through `watch`, ledger record); 85 total.

## 0.5.0 — 2026-11-25
- `key_across_addresses`: one credential used from 3+ addresses **and** 5+ rejected
  requests is one actor, not eight innocent ones. 3 points, 6 when 6+ addresses or
  20+ rejections. A shared *working* key across egress addresses stays low, so the
  rule cannot punish normal infrastructure. This closes the evasion that beat
  every per-address rule (measured: 0/16 before, 16/16 after).
- Corpus grows to 360 benign / 80 attack sessions with two new families
  (`shared_egress_key`, `key_rotator`); held-out seed reproduces the numbers.
- `key_clusters` is reported in the JSON output.
- 75 tests.

## 0.4.0 — 2026-11-25
- Deny list lifecycle: merge with the file on disk (a quiet run no longer lifts
  an unexpired block), drop expired entries, atomic replace, `--deny-max` refuses
  instead of writing a list that costs nginx throughput, `--reload-cmd` runs only
  after a good write and reports its exit status.
- Fail-closed: a corrupt or malformed canary registry exits **4** instead of
  reporting "not planted"; a missing or unparsable log exits **3** instead of 0;
  torn lines are counted (`skipped_lines`).
- `packaging/`: systemd unit + timer, logrotate; `docs/OPERATIONS.md` with exit
  codes, sizing and measured throughput.
- Perf, measured: 100k lines on one path with **one** key 658 s -> **1.20 s**;
  300k lines 5.6 s analyse, 303 MB.
- 69 tests.

## 0.3.0 — 2026-11-25
- `--state` / `--state-ttl`: a cron no longer repeats the same alert every
  minute; escalation is new again, the file is pruned and replaced atomically.
- `X-Forwarded-For` is trusted only from `--trusted-proxy` (CIDR, repeatable);
  a header from an unlisted peer is ignored and recorded as `xff_ignored`.
- `.gz` logs are read directly (rotation needs no unpacking step).
- Quadratic window scans removed: `auth_failure_streak` and `path_burst` use a
  sliding counter; 100k requests from one address now cost 1.19 s.
- `path_burst` (40 paths/min, status-independent, search bots excluded) catches
  the 770-request all-301 scanner on this server's log that scored 1 point.
- Deny gate: volume rules alert but never deny (CDN/NAT); `--deny-unsafe` opts in.
- `tools/bench.py` and a held-out corpus (seed 771122) with identical numbers.
- Depends on `gama-mandate >= 0.43`; 0.44+ contains the linear window scan and is
  recommended (a hard >=0.44 pin made CI fail for ~15 minutes on PyPI CDN lag).
- 60 tests.

## 0.2.0 — 2026-11-25
- Measured false positives: 300 benign sessions -> 0 flagged at any level; 60
  attacks -> 45 high, 60 >= medium. `docs/FALSE_POSITIVES.md` carries the method.
- `tool_switch` 3 -> 2: alone it flagged 50/300 benign sessions (a developer
  switching from a browser to curl).
- Document rules now need corroboration: `docs_link_follow` and
  `spec_derived_novel_path` are suppressed unless the same address also produced
  a 401/403 in the window, or a canary fired.
- One document unlocks one path; a failed document fetch unlocks none.
- `logread`: nginx/Apache combined parser, timezone-aware, `--format auto`.
- `auth_failure_streak` (5+ rejects in 60 s) and `wide_probe` (25+ 4xx paths).
- `--deny-map` / `--deny-json`: nginx lines plus JSON with per-entry expiry;
  loopback, RFC1918, link-local and documentation ranges are never denied.
- `tools/gen_corpus.py` (seeded) and `tools/measure.py` reproduce every number.
- 32 tests.

## 0.1.1 — 2026-11-25
- Percent-encoded values are decoded before canary matching (`%5F` no longer
  slips past a token).
- Tags publish through the `PYPI_API_TOKEN` secret; OIDC stays optional.

## 0.1.0 — 2026-11-25
- First release: planted canaries (registry keeps only SHA-256), spec-derived
  novel paths, base behavioural rules from `mandate.agentwatch`, alerts written
  into the mandate hash chain as `control/alert`.
- 14 tests replaying the reported Nov 2026 sequence.
