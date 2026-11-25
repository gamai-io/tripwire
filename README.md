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
the two things an inbound detector needs and an authorisation log cannot give:

1. **Planted canaries** — credential-shaped strings that no legitimate client
   ever sends. Any use is decisive on its own.
2. **Spec-derived novel paths** — a path whose first appearance follows a fetch
   of an API/spec document within 60 s. A person does not go from reading a spec
   to a never-seen endpoint that fast; a script does.

## Install

```bash
pip install gamai-tripwire      # pulls gama-mandate for the base rules + ledger
```

Runs on Python 3.9+, no services, no model, no network calls at analysis time.

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
               --ledger alerts.jsonl --min-level medium
```

Exit code `0` = nothing at or above `--min-level`, `1` = something is. Findings
are appended to the mandate ledger as `{"type":"control","action":"alert"}` in
the same hash chain as execution receipts, so an alert is evidence too.

Log line (JSONL), one per request:

```json
{"ts": 1795558000.1, "ip": "81.2.3.4", "ua": "Mozilla/5.0 ... Chrome/157",
 "method": "GET", "path": "/api/v1/invoices", "status": 200,
 "ua_platform": "desktop", "auth": "key-A", "referer": "/docs/api.md", "query": ""}
```

`ua_platform` is optional (`desktop`/`mobile`) and is only used for the UA-flip
rule. nginx with `log_format ... escape=json` maps directly; Envoy's JSON access
log needs a three-field rename (`@timestamp`, `useragent`, `:path`).

## Rules and weights

| rule | points | what it sees |
|---|---|---|
| `canary_used` | 10 | a planted key was sent — **critical on its own** |
| `key_probing` | 4 | 3+ distinct auth values (or none) on one path within 60 s |
| `tool_switch` | 3 | browser then curl/wget/httpx from one address within 15 min |
| `docs_link_follow` | 3 | request whose Referer is an API/spec document |
| `spec_derived_novel_path` | 3 | first request to a path right after a spec fetch |
| `ua_flip` | 2 | same address claims desktop and mobile within 5 min |
| `read_after_submit` | 2 | repeated GETs refused by submit-only endpoints |
| `low_and_slow_scan` | 2 | 10+ paths answering 4xx with a single UA |
| `velocity` | 1 | 15+ distinct paths in one minute |

Levels: `critical` (canary), `high` (>=6), `medium` (>=3), else `low`.

## Proof it works on the real timeline

`tests/test_detect.py` replays the reported sequence — refused front page, fake
Android UA 6 s later, API document, path from that document 13 s later, three
auth values within 4 s, submit-only endpoint read twice — and asserts **high**
plus the four decisive rules; a canary in the same log makes it **critical**; a
five-page visitor stays **low**; a quiet log writes nothing to the ledger.

```bash
python -m pytest -q tests/
```

## What this is not

- **Not a WAF and not inline.** It reads logs after the fact; it cannot block a
  request by itself. Use its verdict to drive nginx `deny`, an Envoy filter or a
  key suspension — that is a separate change to your edge.
- **Not TLS-inspecting.** If your edge only logs `CONNECT`, there is nothing to
  score. It needs method, path, status, UA and Referer.
- **Not a model.** There is no ML in the decision path and no LLM in the loop.
  A judge model may explain a finding; it can never lower one.
- **Canaries only work if planted** and only if the same token is not used
  legitimately. Treat a canary hit as an incident, not as a percentage.
- **It will fire on your own scanners and CI** unless you tag or exclude their
  addresses. That is a configuration task, not a bug.
- **Not compliance.** It produces evidence of a detection attempt; it is not a
  certification, and no number here should be read as one.

## Licence

MIT. Part of the gamAI control set: `gama-mandate` (signed approval of an
effect), `gamai-guard` (prompt-injection), `gamai-trust` (claim vs evidence),
`gamai-plugins` (policy/sandbox), `crossnode-bench` (false success).
