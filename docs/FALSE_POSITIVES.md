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

| family | sessions | what it does |
|---|---|---|
| `incident` | 15 | the reported sequence: 403, fake phone UA, decoy doc, path from the doc, 3 keys in 4 s |
| `key_prober` | 15 | 20 keys against one endpoint, 300 ms apart |
| `slow_scanner` | 15 | 30 new paths, one 404 each, 10–20 s apart |
| `docs_crawler` | 15 | spec, then 10 new endpoints with 401 |

### Result (after the tuning described below)

| metric | value |
|---|---|
| benign sessions | 300 |
| benign flagged **high/critical** | **0** (0.0 %) |
| benign flagged **at any level** | **0** (0.0 %) |
| attack sessions | 60 |
| attack flagged **high** | 45 (75 %) |
| attack flagged **medium or higher** | **60 (100 %)** |
| `slow_scanner` | medium only — by design, see below |

Per family, attacks: `incident` 15/15 high, `key_prober` 15/15 high,
`docs_crawler` 15/15 high, `slow_scanner` 15/15 medium.

## 2. This server's own nginx log

```bash
python3 -m tripwire watch --log /var/log/nginx/access.log \
        --window 86400 --min-level medium --deny-map out/deny.map
```

| metric | value |
|---|---|
| requests in the file | 4,048 |
| distinct sources | 238 |
| flagged medium or higher | 4 |
| flagged high | 1 |
| proven false positives | **0** |

Manual labels for the four:

- `116.203.51.159`, `16.170.14.81`, `171.226.11.20` — `POST /wp-login.php` then
  `/wp-json/wp/v2/users?per_page=2`, with the user agent rotating between
  desktop Linux, Android and iPhone, and a `Referer` pointing at another server.
  All three medium (`ua_flip` + `velocity`). Confirmed probing, not customers.
  They answer `301`, not `401`, so the credential rule cannot fire — the UA flip
  is what caught them.
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

## 4. Deny-list safety

`tripwire watch --deny-map` writes nginx `deny` lines and a JSON twin with a
per-entry expiry. Before writing, each address is checked with
`ipaddress.ip_address(ip).is_global`:

- loopback, private, link-local, multicast and documentation ranges are **never**
  denied; they are listed in the file as `# skipped <ip> (<reason>)`;
- `--ignore 198.51.100.9` (repeatable) keeps your own scanner out of the list;
- the list is meant to be rewritten on a timer — expiry is in the file, so a cron
  both adds and removes entries.

## 5. Limits, stated plainly

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
