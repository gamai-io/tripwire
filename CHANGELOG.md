# Changelog

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
