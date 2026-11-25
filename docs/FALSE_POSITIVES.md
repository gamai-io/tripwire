# False positives and misses, measured

Two corpora, one command each. Numbers below were produced by
`tools/measure.py` and by running the detector against this server's own nginx
log. Nothing here is an estimate.

## 1. Synthetic corpus (reproducible)

```bash
python3 tools/gen_corpus.py --out corpus --benign 300 --attack 60 --seed 20261125
python3 tools/measure.py --corpus corpus
```

Sessions are seeded (`20261125`), one source address each, analysed with a window
that contains the whole session, so the result does not depend on when it runs.

| family | sessions | what it does |
|---|---|---|
| `human_reader` | 50 | browser, 6–20 pages, 10–120 s apart |
| `human_docs` | 50 | reads `/docs/api.md`, then 1–3 pages, all 200 |
| `developer_curl` | 50 | browser, spec, then `curl` with a **working** key |
| `crawler` | 50 | Googlebot/Bingbot, 40–120 paths, some 404 |
| `api_client` | 50 | httpx/curl, 50–200 calls, 3–6 paths, valid key |
| `monitoring` | 50 | `curl /health` every 30 s |
| `shared_egress_key` | 60 | one **working** key used from 4 egress addresses |

| family | sessions | what it does |
|---|---|---|
| `incident` | 15 | the reported sequence: 403, fake phone UA, decoy doc, path from the doc, 3 keys in 4 s |
| `key_prober` | 15 | 20 keys against one endpoint, 300 ms apart |
| `slow_scanner` | 15 | 30 new paths, one 404 each, 10–20 s apart |
| `docs_crawler` | 16 | spec, then 10 new endpoints with 401 |
| `key_rotator` | 16 | the same stolen key from 8 addresses, 40 rejected requests |

### Result (after the tuning described below)

| metric | value |
|---|---|
| benign sessions | 360 |
| benign flagged **high/critical** | **0** (0.0 %) |
| benign flagged **at any level** | **0** (0.0 %) |
| attack sessions | 80 |
| attack flagged **high** | 64 (80 %) |
| attack flagged **medium or higher** | **80 (100 %)** |
| `slow_scanner` | medium only — by design, see below |

Per family, attacks: `incident` 16/16 high, `key_prober` 16/16 high,
`docs_crawler` 16/16 high, `key_rotator` 16/16 high, `slow_scanner` 16/16 medium.

### Held-out sample

The tuning decisions above were made on seed `20261125`. The same code was then
run on a fresh sample, seed `771122`, 300 benign and 60 attack sessions:

| metric | tuning seed | held-out seed |
|---|---|---|
| benign flagged (any level) | 0 / 360 | **0 / 360** |
| attacks high | 64 / 80 | **64 / 80** |
| attacks medium or higher | 80 / 80 | **80 / 80** |

Identical, which is what one hopes for and not the same thing as proof: both
samples come from the same generator, so this rules out seed luck, not model
error.

## 2. This server's own nginx log

```bash
python3 -m tripwire watch --log /var/log/nginx/access.log \
        --window 86400 --min-level medium --deny-map out/deny.map
```

| metric | value |
|---|---|
| requests in the file | 4,048 |
| distinct sources | 238 |
| flagged medium or higher | 5 |
| flagged high | 1 |
| proven false positives | **0** |

Manual labels for the four:

- `116.203.51.159`, `16.170.14.81`, `171.226.11.20` — `POST /wp-login.php` then
  `/wp-json/wp/v2/users?per_page=2`, with the user agent rotating between
  desktop Linux, Android and iPhone, and a `Referer` pointing at another server.
  All three medium (`ua_flip` + `velocity`). Confirmed probing, not customers.
  They answer `301`, not `401`, so the credential rule cannot fire — the UA flip
  is what caught them.
- `14.102.84.54` — 770 requests over four minutes against one vhost, 184 per
  minute, every answer a `301`. No 4xx anywhere, so the 4xx rules never fire;
  `path_burst` catches it at **medium** (this is the case that motivated the rule).
- `127.0.0.1` — our own scanner. High, and **excluded from the deny list**
  because a loopback address is never blockable.

"0 proven false positives" means every flagged address was inspected; it does
not mean every unflagged address is clean.

## 3. What the measurement changed

All four changes came from corpus runs, not from taste.

| change | why |
|---|---|
| `tool_switch` weighs **2**, not 3 | alone it flagged 50 of 300 benign sessions — every developer who switches from browser to `curl`. At 2 it is a point of interest, not an incident; the `incident` family still reaches high on other rules. |
| document rules need **corroboration** | `docs_link_follow` + `spec_derived_novel_path` = 6 points = high for anyone reading the spec. They now count only if the same address also produced a `401`/`403` in the window, or a canary fired. This is the exact discriminator in the reported intrusion. |
| one document unlocks **one** path | before, a single request to a doc-ish path made every new path in the next 60 s "spec-derived"; a scanner walking 300 paths produced ~300 findings. The incident shape is one document → one followed link. |
| failed document fetch does **not** unlock | a `403` on `/docs/api.md` is not a document we served, so nothing can be derived from it. |
| `key_across_addresses` added | the one evasion that beat every per-address rule: the same credential from 8 addresses scored **nothing**. It now scores 6 when 6+ addresses or 20+ rejections; a *working* key shared by 4 egress addresses stays low because the rule also needs the failures. |
| `path_burst` added (40 paths/min, status-independent) | a scanner behind a redirect-heavy vhost answers `301` to everything and scored 1 point on this server's own log. Search crawlers are excluded by user agent, so the corpus `crawler` family stays at 0 false positives. |
| the window is measured against the file, not the clock | `--window 600` on a log from yesterday produced `0 sources, 0 flagged, exit 0` — a clean bill of health for a file that was never read. The default `now` is now the newest row; an empty file exits 3. |
| a canary opens its own case | a canary hit whose row fell outside the window was counted in `canary_hits` but produced no session, so `flagged` stayed 0. The hit now synthesises a session at `critical`. |
| timezone from `timegm`, not `mktime` | `mktime` shifted every parsed line by the host's UTC offset (1 h here, 2 h across DST) and silently moved rows in and out of the window. |

## 4. Deny-list safety

`tripwire watch --deny-map` writes nginx `deny` lines and a JSON twin with a
per-entry expiry. Before writing, each address is checked with
`ipaddress.ip_address(ip).is_global`:

- loopback, private, link-local, multicast and documentation ranges are **never**
  denied; they are listed in the file as `# skipped <ip> (<reason>)`;
- `--ignore 198.51.100.9` (repeatable) keeps your own scanner out of the list;
- **behaviour never denies.** `ua_flip` + `tool_switch` + `velocity` from one
  address is what a shared NAT with a laptop, a phone and one script looks like; it
  alerts and is reported as `behaviour only`, and is not blocked.
- **volume rules never deny.** `velocity`, `wide_probe`, `path_burst` and
  `low_and_slow_scan` fire on shared egress — a CDN, a corporate NAT, a hospital
  with one line. Denial needs a canary, probed or rejected credentials, two
  independent behaviours, or one behaviour plus five failures; otherwise the
  address is alerted and reported as `volume evidence only`. `--deny-unsafe`
  overrides, deliberately named;
- the list is meant to be rewritten on a timer — expiry is in the file, so a cron
  both adds and removes entries.

## 5. Scans spread across addresses

Per-address rules are blind to two requests per address from a thousand addresses.
`path_baseline_anomaly` compares the distinct-source count on a path template
(`/api/v1/invoices/8812` → `/api/v1/invoices/{}`) with an EWMA of its own history.

- 4 clean windows of 5 sources, then 70 sources on one path → **1 anomaly**, and
  the anomalous window is **not** folded into the history (`tests/test_baseline.py`).
- it reports the path, not the addresses: blaming individual addresses on a shared
  endpoint is how a detector blocks a CDN.
- it needs warm-up; a path seen for the first time is never an anomaly, and the
  factor (default 3x) plus a floor (default 10 sources) are per-deployment knobs.

## 6. Limits, stated plainly

- The synthetic corpus is a model of traffic, not traffic. It shows the rules do
  what they say on the shapes they were designed for; it cannot prove behaviour
  on a real bank's API.
- `combined` logs carry no credential value, so `key_probing` and
  `auth_failure_streak` can only fire on the JSONL schema (which includes
  `auth`). On a combined log you get behaviour, not credential attempts.
- Recall is measured on 60 attacks of four families. A patient attacker who
  reads the spec, uses a valid key and never fails an auth check looks like a
  developer **by construction**; the detector will not separate them. That is a
  documented limit, not a bug to be papered over.
- `slow_scanner` lands on medium. Raising it to high would require calling every
  slow 404 walk an incident; the deny threshold defaults to medium instead.
- Thresholds are global, not per-API. Per-path baselines are future work.
- The corpus is a model of traffic written by the same person who wrote the
  detector. A held-out seed shows the numbers are not seed luck; it says nothing
  about a real bank's API. That needs a design partner's log, with labels.
- Behind a CDN every request looks like it comes from the CDN. `--trusted-proxy`
  fixes the address only when the proxy is pinned; a log that never recorded
  `X-Forwarded-For` cannot be repaired afterwards.
- Denial is deliberately conservative: on this server's real log, **zero**
  addresses qualify (the three WordPress probes answer `301`, so no credential
  failure is visible; one behaviour plus volume is not enough). That is the
  designed behaviour, not a bug — `--deny-unsafe` exists for operators who
  accept the CDN risk.
