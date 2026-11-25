# Claims and how to check them

| claim | value | command |
|---|---|---|
| version | 0.3.0 | `python3 tools/claims.py --version` |
| tests | 60 | `python3 -m pytest -q tests/` |
| benign sessions flagged | 0 / 300 | `python3 tools/gen_corpus.py --out corpus && python3 tools/measure.py --corpus corpus` |
| attacks at high | 45 / 60 | same command |
| attacks at medium+ | 60 / 60 | same command |

## Not proven here

- Detection inside a real bank's API: not run.
- Sustained throughput at 50M lines/day: not measured yet.
- Evasion by a patient attacker with a valid key: not detectable by design.
