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
   a minute, twenty-five distinct paths answering 4xx, forty distinct paths in a
   minute whatever the status.
4. **Corroboration** — the two document rules only count when the same address
   also failed an auth check. Reading the spec is not an attack; failing the
   check right after is. This is the discriminator the incident report named.
5. **A deny list you can actually apply** — nginx lines plus JSON with an expiry
   per entry, and loopback/private addresses are never blocked.

## Install

```bash
pip install gamai-tripwire      # pulls gama-mandate >= 0.43 for the base rules + ledger
```

Python 3.9+, no services, no model, no network calls at analysis time.

## Plant canaries

```bash
tripwire canary generate --count 3 --registry canaries.json \
        --plant-dir /var/www/decoy    # writes decoy docs containing the tokens
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

**Behind a CDN or a load balancer** every request arrives from the proxy, so the
peer address is not the client. Either let nginx resolve it
(`set_real_ip_from <proxy>; real_ip_header X-Forwarded-For;` — then `combined`
already carries the real client), or include `xff` in the JSONL line and name the
proxy:

```bash
tripwire watch --log access.jsonl --trusted-proxy 10.0.0.0/8 --trusted-proxy 104.16.0.0/13
```

`X-Forwarded-For` from an address you did **not** list is ignored and recorded as
`xff_ignored`, because otherwise anyone can pick someone else's address and get
that address blocked.

**Deny list.** `--deny-map` writes `deny <ip>;` lines with a comment per entry
carrying `expires=<epoch>`; `--deny-json` writes the same as data. It **merges
with the file already on disk** (an unexpired block survives a quiet minute),
drops expired entries, replaces the file atomically, refuses to grow past
`--deny-max` (default 1000 — a huge list costs nginx throughput), and runs
`--reload-cmd` only after a good write. Apply the list from your edge; the tool
never rewrites firewall state itself. Three gates before an address is blocked:

1. **Global unicast only** — loopback, RFC1918, link-local and documentation
   ranges are skipped and reported: blocking them takes the service down.
2. **Identity, not behaviour** — denial needs a canary, probed or rejected
   credentials, or one credential used across several addresses *with* a failure
   ratio. Behaviour (`ua_flip`, `tool_switch`, `velocity`, `path_burst`) only
   alerts: a laptop, a phone and one curl script behind a shared NAT look exactly
   like an intruder. `--deny-unsafe` opts into volume-based blocking.
3. **Expiry in the file** — a cron that re-runs `watch` both adds and removes.

`--ignore <ip>` (repeatable) keeps your own scanner out.

**A scan spread across many addresses.** Per-address rules cannot see it. Keep a
per-path history and the endpoint's own baseline catches it:

```bash
tripwire watch --log access.jsonl --window 600 \
        --baseline /var/lib/tripwire/baseline.json --baseline-factor 3 --baseline-floor 10
```

Anomalies are reported per **path**, not per address, and a window that trips the
baseline is **not** folded into the history, so an attack cannot normalise itself.
It needs a few clean runs first; a cold path is never an alarm.

**Not shouting every minute.** A cron that re-runs `watch` over the same file
needs `--state`:

```bash
tripwire watch --log access.jsonl --state /var/lib/tripwire/state.json --state-ttl 3600
# output: new_alerts=0 when nothing changed; an escalation is new again
```

The state file keeps the last level per address with an expiry, is pruned on
every write and is replaced atomically.

**Rotation.** `.gz` files are read directly, so `access.log.1.gz` needs no
unpacking step.

**Time.** The window is measured against the **newest row in the file**, not the
wall clock, so a log written yesterday is still analysed. `--now wall` for live
tailing, `--now <epoch>` for a fixed cut-off. An empty or unparsable file exits
**3** and says `no rows` — it never reports "clean".

## Rules and weights

| rule | points | what it sees |
|---|---|---|
| `canary_used` | 10 | a planted key was sent — **critical on its own** |
| `path_baseline_anomaly` | report | a path whose distinct-source count is 3x its own history (needs `--baseline`) |
| `key_across_addresses` | 3–6 | one credential from 3+ addresses **and** 5+ rejected requests (6 when 6+ addresses or 20+ rejections) |
| `key_probing` | 4 | 3+ distinct auth values (or none) on one path within 60 s |
| `auth_failure_streak` | 4 | 5+ rejected credentials on one endpoint within 60 s |
| `spec_derived_novel_path` | 3 | first request to a path right after a spec fetch |
| `docs_link_follow` | 3 | request whose Referer is an API/spec document |
| `read_after_submit` | 2 | repeated GETs refused by submit-only endpoints |
| `ua_flip` | 2 | same address claims desktop and mobile within 5 min |
| `path_burst` | 3 | 40+ distinct paths in 60 s, whatever the status (search bots excluded) |
| `wide_probe` | 2 | 25+ distinct paths answering 4xx |
| `tool_switch` | 2 | browser then curl/wget/httpx from one address within 15 min |
| `low_and_slow_scan` | 2 | 10+ paths answering 4xx with a single UA |
| `velocity` | 1 | 15+ distinct paths in one minute |

Levels: `critical` (canary), `high` (>=6), `medium` (>=3), else `low`.
`spec_derived_novel_path` and `docs_link_follow` are **suppressed** unless the
same address failed a `401`/`403` in the window or a canary fired.

Replay the reported sequence and watch the score grow request by request:

```bash
python3 tools/replay.py
# t+29s  GET /api/v1/transactions  200  10  high
# first high: t+29s — a replay scored after the fact, not a live block
```

## Measured, not asserted

```bash
python3 tools/gen_corpus.py --out corpus --benign 360 --attack 80 --seed 20261125
python3 tools/measure.py --corpus corpus
```

| corpus | result |
|---|---|
| 360 benign sessions (adds a service that shares one **working** key across 4 egress addresses) | **0 flagged**, at any level |
| 80 attack sessions (adds a key rotated across 8 addresses) | **64 high**, **80 medium or higher** |
| **held-out corpus**, different seed (771122), same 360/80 split | **0 flagged**, **64 high**, **80 medium+** — identical to the tuning seed |
| this server's nginx log: 4,048 requests, 238 sources | 5 flagged ≥ medium, **0 proven false positives**, 3 confirmed WordPress probing + a 770-path scanner that answers only 301 |
| 100,000 requests from one address on one path, one key | **1.20 s** with gama-mandate 0.44+ (658 s before the fix, and zero findings) |

Method, per-family tables and the four changes the measurement forced (including
`tool_switch` dropping from 3 to 2 because it flagged 50 of 300 benign sessions)
are in [`docs/FALSE_POSITIVES.md`](docs/FALSE_POSITIVES.md). Re-running the two
commands reproduces every number.

## Files bigger than memory

`--stream` keeps only the window instead of the whole file. Same verdicts, a
fraction of the RAM; measured on 500,000 lines from 200 addresses:

| mode | window | peak RSS | time |
|---|---|---|---|
| batch (default) | 600 s | **492 MB** | 11.9 s |
| `--stream --chunk 200000` | 600 s | **34 MB** | 3.6 s |

```bash
tripwire watch --log access.log --stream --window 600 --chunk 200000
```

`--chunk` rows are scored together and the findings are unioned per source, with
points taking the maximum. A chunk boundary can lose a timing correlation between
two rules; it cannot invent one. `rows_in_window` in the output tells you what the
window actually held.

## Run it every minute

```bash
cp packaging/tripwire-watch.* /etc/systemd/system/
systemctl enable --now tripwire-watch.timer
```

The window is the memory, so a timer gives tail-like coverage without a daemon.
Exit codes are part of the contract: `0` clean, `1` findings, `3` **could not
analyse** (missing or unparsable log), `4` **refused** (unreadable canary
registry, deny cap hit). Deployment shape, ledger rotation, measured throughput
and what is deliberately missing are in
[`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## Tests

```bash
python -m pytest -q tests/
```

101 tests: the reported timeline scores **high** with all four decisive rules; a
canary in the same log is **critical**; a developer switching to `curl` stays
**low**; a doc reader without a failed check is suppressed; one document unlocks
one path; a redirect-heavy scan is caught without any 4xx; a search bot is not a
burst; loopback is never denied; volume evidence alone never denies; a log from
yesterday is still analysed; combined and JSONL logs agree.

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
