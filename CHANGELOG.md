# Changelog

## 0.8.11 — 2026-11-26
- The claims gate ran the suite twice per README match, so a transient pytest
  failure produced "claims 143 tests, suite has 143 passing" and failed CI. It now
  runs once and says "could not run the suite" instead of inventing a drift.

## 0.8.10 — 2026-11-26
- **A source-rotating flood is refused, not half-scored.** `--stream` memory is
  bounded per source; a window with hundreds of thousands of distinct addresses
  (measured: 500,000 sources ≈ 914 MB) could exhaust the box. `--max-sources`
  (default 200,000) now makes the run exit 3 with `TooManySources` and write
  nothing, instead of dropping the excess and reporting a clean run. The batch
  path refuses too. Four tests, including the CLI exit code.
- Docs state the measured 500,000-source figure and the cap.

## 0.8.9 — 2026-11-26
- Docs: the bot-UA exemption is described as it now works (a source loses it once
  it fails auth); the provenance example points at the current release.
- Supply chain: Actions pinned by commit SHA, the pre-publish secret scan runs
  before upload, and the duplicate `attest.yml` is gone (the publish step creates
  the PEP 740 attestation from the same build).
- Release workflow: no `skip-existing`, so a force-moved tag fails instead of
  leaving PyPI behind while GitHub gets new files.

## 0.8.8 — 2026-11-26
Fourth review (RT4) plus the remaining low items from RT3.

- **`--stream --window 0` no longer hides multi-event rules.** A zero window means
  "the whole file"; the stream path trimmed by zero and dropped everything except
  the newest row, reporting a clean run. It now delegates to the batch path.
- **Out-of-order timestamps** no longer leave stale rows in the window forever:
  a row already outside the window is not admitted, and a decreasing timestamp
  re-orders the deque once before pruning.
- **A partial deny write cannot reach nginx.** Files are staged first and only
  replaced after both wrote; the JSON is written before the map the apply unit
  watches. A failure leaves the previous list untouched.
- **A failed state write is reported, not fatal.** The ledger record is already
  appended; the run now returns `state_error` and prints to stderr instead of
  crashing and duplicating the alert on the next run.
- **Path anomalies remember the source set.** A new campaign on the same path with
  a different source fingerprint is new again, not suppressed as a repeat.
- Spoofed good-bot UAs no longer evade `path_burst`: the exemption applies only
  when that source has zero 401/403 in the window.
- Lines longer than 1 MiB are drained and counted (`oversize_lines`) instead of
  being read whole.
- JSONL with duplicate keys and timestamps outside 2000..now+10y are refused and
  counted (`duplicate_keys`, `bad_timestamps`); combined logs validate hour 99
  instead of normalising it.
- `--trusted-proxy` refuses a prefix wider than /16 (IPv4) or /48 (IPv6) unless
  `--allow-wide-proxy` is passed.
- Docs: the `/8` proxy example is gone; reader refusals and `window 0` semantics
  are stated.

## 0.8.7 — 2026-11-26
Third adversarial review (RT3). The library was tested; the shipped CLI was not.

- **The CLI now forwards `--min-level`, `--state`, `--state-ttl` and
  `--exceptions`.** They were parsed and dropped, so the ledger filter, the
  repeat suppression and the whitelist were dead on the only interface users
  get. A medium alert was written at `--min-level high`, `--state` created no
  file, and an excepted address was still denied. Tests now drive `cli.main`.
- **`path_anomaly` obeys `--state` and `--exceptions`.** It repeated forever
  (one ledger line per run) and ignored the window. It is remembered by path
  template, sources on an active exception suppress it, and a window that trips
  twice in a row is folded into the baseline so it cannot alert forever.
- **Refusals are refusals.** `--deny-max` exceeded called `_emit(obj, None)` and
  died with `TypeError`/exit 1; a deny path that could not be written raised a
  traceback. Both are exit 4 with JSON now.
- **A deny list on disk is untrusted input.** Previously written entries are
  re-validated (private/loopback dropped) and re-emitted from validated fields,
  so a JSON `ip` containing `\nallow all` can no longer inject nginx directives.
  An active exception lifts a block that is already on disk.
- **The shipped unit is now two units.** The unprivileged watch unit writes
  `/var/lib/tripwire/deny.conf`; a root oneshot apply unit runs `nginx -t` and
  restores the previous file if nginx rejects it. `SupplementaryGroups=adm`
  makes the 0640 nginx log readable, and `nginx -s reload` no longer has to run
  as an unprivileged user.
- **A stale 401 no longer corroborates today's session.** `by_ip` is built from
  the window, not the whole file.
- **A future-dated row no longer blinds `--stream`.** Rows more than 60 s ahead
  are counted and skipped; a file with rows but none inside the window is
  "could not analyse" (exit 3), not "clean".
- **Non-numeric `ts`/`status` no longer crash.** They are skipped/counted, not
  raised inside the analyser.
- Streaming prunes sessions that have left the window, so memory is bounded by
  sources in the window; the doc numbers are corrected (146 MB / 2.46 s for
  100k rows, 200 sources).
- A missing explicit `--registry` is refused (exit 4) instead of silently
  disabling canaries; `canary revoke/generate` refuse a corrupt registry instead
  of overwriting it with an empty one.
- `--reload-cmd` runs only when the list actually changed (it ran every minute
  for as long as any block lived).
- The sdist ships `packaging/`, `tools/`, `CLAIMS.md`, `CHANGELOG.md` and
  `SECURITY.md`, which the README already told people to run.
- `SECURITY.md` documents OIDC trusted publishing (the token section was stale)
  and the supported-version table; the claims gate now checks `CLAIMS.md`, the
  supported version and the corpus numbers, not only the README test count.
- Docs corrected: per-family table (16 each, not 15/15/15/16/16), "80 attacks of
  five families", identity-only deny evidence (the "two behaviours" path was
  never implemented), exit-code table, `rows_in_window`/`invalid_rows`, and the
  logrotate `copytruncate` warning.

## 0.8.6 — 2026-11-26
- The sdist now carries `docs/` (it only shipped README, tests and the package),
  so the measured false-positive report travels with the release instead of
  existing only in git.

## 0.8.5 — 2026-11-26
- `docs/FALSE_POSITIVES.md` said the held-out sample was 300/60 while the table
  in the same section showed 0/360, 64/80 and 80/80. It is 360 benign and 80
  attack sessions.

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
