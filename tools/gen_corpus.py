#!/usr/bin/env python3
"""Generate a labelled corpus: benign sessions and attack sessions.

Deterministic (seeded), so a false-positive number can be re-checked by anyone.
Each session is one JSONL file with a single source address, which is how the
detector groups rows, and the manifest says what the session really was.

    python3 tools/gen_corpus.py --out corpus --benign 300
    python3 tools/measure.py --corpus corpus
"""
from __future__ import annotations

import argparse
import json
import os
import random

BENIGN_IPS = ["203.0.113.%d" % i for i in range(1, 250)]
ATTACK_IPS = ["198.51.100.%d" % i for i in range(1, 250)]

DESKTOP = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36")
MAC_SAFARI = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/{v}.0 Safari/605.1.15")
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"
PHONE = ("Mozilla/5.0 (Linux; Android 15; Pixel 10) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/{v}.0.0.0 Mobile Safari/537.36")
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BINGBOT = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
CURL = "curl/8.7.1"
HTTPX = "python-httpx/0.27.0"

PAGES = ["/", "/pricing", "/models.html", "/contact.html", "/savings.html",
         "/agent-audit.html", "/sigil.html", "/benchmarks.html", "/verify.html"]
API = ["/api/v1/invoices", "/api/v1/customers", "/api/v1/reports",
       "/api/v1/reports/summary", "/api/v1/reports/2026-11", "/api/v1/accounts"]
DOCS = ["/docs/api.md", "/api/openapi.json", "/docs/getting-started.md"]


def row(ts, ip, ua, path, status=200, method="GET", auth="none", referer=""):
    return {"ts": round(ts, 3), "ip": ip, "ua": ua, "method": method, "path": path,
            "status": status, "auth": auth, "referer": referer,
            "ua_platform": "mobile" if "Mobile" in ua else "desktop"}


def human_reader(rng, ip, start):
    ua = rng.choice([DESKTOP.format(v=rng.randint(120, 140)),
                     MAC_SAFARI.format(v=rng.randint(15, 18)),
                     FIREFOX.format(v=rng.randint(120, 135))])
    rows, ts, last = [], start, "/"
    for _ in range(rng.randint(6, 20)):
        path = rng.choice(PAGES + ["/docs", "/blog"])
        ts += rng.uniform(10, 120)
        rows.append(row(ts, ip, ua, path, referer="" if last == "/" else last))
        last = path
    return rows


def human_docs(rng, ip, start):
    """Reads the spec, then uses the product. The hard benign case."""
    ua = rng.choice([DESKTOP.format(v=rng.randint(120, 140)),
                     MAC_SAFARI.format(v=rng.randint(15, 18))])
    rows, ts = [], start
    ts += rng.uniform(5, 30)
    rows.append(row(ts, ip, ua, "/"))
    ts += rng.uniform(20, 90)
    doc = rng.choice(DOCS)
    rows.append(row(ts, ip, ua, doc, referer="/"))
    for page in rng.sample(PAGES, rng.randint(1, 3)):
        ts += rng.uniform(20, 120)
        rows.append(row(ts, ip, ua, page, referer=doc))
    return rows


def developer_curl(rng, ip, start):
    """Browser, spec, then curl with a key that works. Must stay low."""
    ua = DESKTOP.format(v=rng.randint(120, 140))
    rows, ts = [], start
    for page in ["/", "/pricing", "/docs"]:
        ts += rng.uniform(5, 40)
        rows.append(row(ts, ip, ua, page))
    ts += rng.uniform(10, 60)
    rows.append(row(ts, ip, ua, "/docs/api.md", referer="/docs"))
    for _ in range(rng.randint(5, 15)):
        ts += rng.uniform(2, 30)
        rows.append(row(ts, ip, CURL, rng.choice(API), auth="key-valid"))
    return rows


def crawler(rng, ip, start):
    ua = rng.choice([GOOGLEBOT, BINGBOT])
    rows, ts = [], start
    for _ in range(rng.randint(40, 120)):
        ts += rng.uniform(0.5, 5)
        path = rng.choice(PAGES + ["/sitemap.xml", "/robots.txt"])
        status = 404 if rng.random() < 0.05 else (200 if rng.random() < 0.9 else 301)
        rows.append(row(ts, ip, ua, path, status=status))
    return rows


def api_client(rng, ip, start):
    ua = rng.choice([HTTPX, CURL])
    rows, ts = [], start
    paths = rng.sample(API, rng.randint(3, min(6, len(API))))
    for _ in range(rng.randint(50, 200)):
        ts += rng.uniform(0.2, 2)
        rows.append(row(ts, ip, ua, rng.choice(paths), auth="key-valid"))
    return rows


def monitoring(rng, ip, start):
    rows, ts = [], start
    for _ in range(20):
        ts += rng.uniform(25, 35)
        rows.append(row(ts, ip, CURL, rng.choice(["/health", "/health/ready"])))
    return rows


BENIGN = {"human_reader": human_reader, "human_docs": human_docs,
          "developer_curl": developer_curl, "crawler": crawler,
          "api_client": api_client, "monitoring": monitoring}


def incident(rng, ip, start):
    """The reported sequence, reproduced as a session."""
    ua = DESKTOP.format(v=157)
    phone = PHONE.format(v=157)
    ts = start
    rows = [row(ts, ip, ua, "/", 403),
            row(ts + 6, ip, phone, "/", 403),
            row(ts + 11, ip, ua, "/api/openapi.json", 403),
            row(ts + 16, ip, ua, "/decoy/openapi.md")]
    ts += 29
    rows.append(row(ts, ip, ua, "/api/v1/transactions", referer="/decoy/openapi.md"))
    for auth in ("key-A", "none", "made-up"):
        ts += 2
        rows.append(row(ts, ip, CURL, "/api/v1/transactions", 401, auth=auth))
    ts += 10
    for _ in range(2):
        ts += 10
        rows.append(row(ts, ip, CURL, "/api/v1/transactions/read", 405))
    return rows


def key_prober(rng, ip, start):
    rows, ts = [], start
    for i in range(20):
        ts += 0.3
        rows.append(row(ts, ip, CURL, "/api/v1/invoices", 401, auth="k-%d" % i))
    return rows


def slow_scanner(rng, ip, start):
    rows, ts = [], start
    for i in range(30):
        ts += rng.uniform(10, 20)
        rows.append(row(ts, ip, CURL, "/api/v1/resource/%d" % i, 404))
    return rows


def docs_crawler(rng, ip, start):
    rows, ts = [], start
    rows.append(row(ts, ip, CURL, "/docs/api.md"))
    for i in range(10):
        ts += rng.uniform(15, 25)
        rows.append(row(ts, ip, CURL, API[i % len(API)] + "/%d" % i, 401,
                        referer="/docs/api.md"))
    return rows


ATTACK = {"incident": incident, "key_prober": key_prober,
          "slow_scanner": slow_scanner, "docs_crawler": docs_crawler}


def write_session(directory: str, name: str, rows: list[dict]) -> str:
    path = os.path.join(directory, name + ".jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        for item in rows:
            fh.write(json.dumps(item, sort_keys=True) + "\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="corpus")
    ap.add_argument("--benign", type=int, default=300)
    ap.add_argument("--attack", type=int, default=60)
    ap.add_argument("--seed", type=int, default=20261125)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    benign_dir = os.path.join(args.out, "benign")
    attack_dir = os.path.join(args.out, "attack")
    os.makedirs(benign_dir, exist_ok=True)
    os.makedirs(attack_dir, exist_ok=True)

    manifest = []
    kinds = list(BENIGN)
    for i in range(args.benign):
        kind = kinds[i % len(kinds)]
        ip = BENIGN_IPS[i % len(BENIGN_IPS)]
        start = 1.795000000e9 + i * 700
        rows = BENIGN[kind](rng, ip, start)
        path = write_session(benign_dir, "%s-%03d" % (kind, i), rows)
        manifest.append({"file": path, "label": "benign", "kind": kind,
                         "requests": len(rows)})

    kinds = list(ATTACK)
    for i in range(args.attack):
        kind = kinds[i % len(kinds)]
        ip = ATTACK_IPS[i % len(ATTACK_IPS)]
        start = 1.795000000e9 + i * 700
        rows = ATTACK[kind](rng, ip, start)
        path = write_session(attack_dir, "%s-%03d" % (kind, i), rows)
        manifest.append({"file": path, "label": "attack", "kind": kind,
                         "requests": len(rows)})

    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"seed": args.seed, "sessions": manifest}, fh, indent=1, sort_keys=True)
    print("wrote %d sessions to %s" % (len(manifest), args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
