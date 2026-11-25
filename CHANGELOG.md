# Changelog

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
