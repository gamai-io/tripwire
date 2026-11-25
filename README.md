# gamai-tripwire

Detect an **inbound** AI agent by what it does, not by who it claims to be.

Built from the November 2026 incident in which an attacker used an open-source
coding agent, a browser and `curl` against a financial firm: no blocklist
matched the address, and the only reliable signal was behaviour — a desktop
browser that switched to a fake phone user-agent, then to `curl`, from one
address inside a few minutes; a request for a path that existed only inside an
API document served seconds earlier; the same key, no key and a fabricated key
tried against one endpoint within seconds.

`mandate watch` (in `gama-mandate`) scores those behaviours. This package adds
what an inbound detector needs and an authorisation log cannot give:

1. **Planted canaries** — credential-shaped strings that no legitimate client
   ever sends. Any use is decisive on its own.
2. **Spec-derived novel paths** — a path whose first appearance follows a fetch
   of an API/spec document within 60 s, one path per document.
3. **Credential and probe rules** — five rejected credentials on one endpoint in
   a minute, twenty-five distinct paths answering 4xx.
4. **Corroboration** — the two document rules only count when the same address
   also failed an auth check. Reading the spec is not an attack; failing the
   check right after is. This is the discriminator the incident report named.
5. **A deny list you can actually apply** — nginx lines plus JSON with an expiry
   per entry, and loopback/private addresses are never blocked.

## Install

```bash
pip install gamai-tripwire      # pulls gama-mandate for the base rules + ledger
```

Python 3.9+, no services, no model, no network calls at analysis time.

## Plant canaries

```bash
tripwire canary generate --count 3 --note "planted in /docs/api.md" --registry canaries.json
# prints the tokens ONCE; only their sha256 is stored
tripwire canary list     --registry canaries.json
tripwire check --token tw_xxx --registry canaries.json      # exit 0 = planted
tripwire canary revoke --id 3f9c1a2b4d5e --registry canaries.json
```

Put one token in each place an intruder reads: a decoy API document, a sample
`.env`, a runbook, a Git history you know is scraped. A leaked registry does not
leak the tokens, so an attacker cannot learn what to avoid.

## Watch an access log

```bash
tripwire watch --log access.jsonl --registry canaries.json --window 600 \
               --ledger alerts.jsonl --min-level medium \
               --deny-map out/deny.map --deny-json out/deny.json --deny-ttl 3600
```

Exit code `0` = nothing at or above `--min-level`, `1` = something is. Findings
are appended to the mandate ledger as `{"type":"control","action":"alert"}` in
the same hash chain as execution receipts, so an alert is evidence too.

**Formats.** `--format auto` (default) detects the file: our JSONL, or the
`combined` format that nginx and Apache write by default. Combined logs carry no
credential value, so the two credential rules need the JSONL schema.

JSONL line, one per request:

```json
{"ts": 1795558000.1, "ip": "81.2.3.4", "ua": "Mozilla/5.0 ... Chrome/157",
 "method": "GET", "path": "/api/v1/invoices", "status": 200,
 "ua_platform": "desktop", "auth": "key-A", "referer": "/docs/api.md", "query": ""}
```

For nginx: `log_format ... escape=json` gives this shape directly; a combined log
needs no change at all.

**Deny list.** `--deny-map` writes `deny <ip>;` lines with a comment per entry
carrying `expires=<epoch>`; `--deny-json` writes the same as data. Addresses that
are not global unicast (loopback, RFC1918, link-local, documentation ranges) are
skipped and reported, because blocking them takes the service down instead of
the intruder. `--ignore <ip>` (repeatable) keeps your own scanner out.

## Rules and weights

| rule | points | what it sees |
|---|---|---|
| `canary_used` | 10 | a planted key was sent — **critical on its own** |
| `key_probing` | 4 | 3+ distinct auth values (or none) on one path within 60 s |
| `auth_failure_streak` | 4 | 5+ rejected credentials on one endpoint within 60 s |
| `spec_derived_novel_path` | 3 | first request to a path right after a spec fetch |
| `docs_link_follow` | 3 | request whose Referer is an API/spec document |
| `read_after_submit` | 2 | repeated GETs refused by submit-only endpoints |
| `ua_flip` | 2 | same address claims desktop and mobile within 5 min |
| `wide_probe` | 2 | 25+ distinct paths answering 4xx |
| `tool_switch` | 2 | browser then curl/wget/httpx from one address within 15 min |
| `low_and_slow_scan` | 2 | 10+ paths answering 4xx with a single UA |
| `velocity` | 1 | 15+ distinct paths in one minute |

Levels: `critical` (canary), `high` (>=6), `medium` (>=3), else `low`.
`spec_derived_novel_path` and `docs_link_follow` are **suppressed** unless the
same address failed a `401`/`403` in the window or a canary fired.

## Measured, not asserted

```bash
python3 tools/gen_corpus.py --out corpus --benign 300 --attack 60 --seed 20261125
python3 tools/measure.py --corpus corpus
```

| corpus | result |
|---|---|
| 300 benign sessions (readers, doc readers, developers on `curl`, crawlers, API clients, monitoring) | **0 flagged**, at any level |
| 60 attack sessions (incident replay, key prober, slow scanner, docs crawler) | **45 high**, **60 medium or higher** |
| this server's nginx log: 4,048 requests, 238 sources | 4 flagged ≥ medium, **0 proven false positives**, 3 confirmed WordPress probing |

Method, per-family tables and the four changes the measurement forced (including
`tool_switch` dropping from 3 to 2 because it flagged 50 of 300 benign sessions)
are in [`docs/FALSE_POSITIVES.md`](docs/FALSE_POSITIVES.md). Re-running the two
commands reproduces every number.

## Tests

```bash
python -m pytest -q tests/
```

32 tests: the reported timeline scores **high** with all four decisive rules; a
canary in the same log is **critical**; a developer switching to `curl` stays
**low**; a doc reader without a failed check is suppressed; one document unlocks
one path; loopback is never denied; combined and JSONL logs agree.

## What this is not

- **Not a WAF and not inline.** It reads logs after the fact; blocking is the
  `--deny-map` file plus your edge.
- **Not TLS-inspecting.** If the edge only logs `CONNECT`, there is nothing to
  score.
- **Not a model.** No ML and no LLM in the decision path; a judge may explain a
  finding, never lower it.
- **Canaries only work if planted**, and it will fire on your own scanners
  unless you `--ignore` them.
- **Not a certificate.** It is evidence that a detection ran.
- **A patient attacker with a valid key who never fails an auth check looks like
  a developer.** Documented limit; per-path baselines are future work.

## Licence

MIT. Part of the gamAI control set: `gama-mandate` (signed approval of an
effect), `gamai-guard` (prompt-injection), `gamai-trust` (claim vs evidence),
`gamai-plugins` (policy/sandbox), `crossnode-bench` (false success).
