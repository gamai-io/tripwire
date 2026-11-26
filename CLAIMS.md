# Claims and how to check them

| claim | value | command |
|---|---|---|
| version | 0.8.14 | `python3 tools/claims.py --version` |
| tests collected | 158 | `python3 -m pytest -q --collect-only tests/` |
| tests failed | 0 | `python3 -m pytest -q tests/` (failures must be 0) |
| benign sessions flagged | 0 / 360 | `python3 tools/gen_corpus.py --out corpus --benign 360 --attack 80 && python3 tools/measure.py --corpus corpus` |
| attacks at high | 64 / 80 | same command |
| attacks at medium+ | 80 / 80 | same command |

## Not proven here

- Detection inside a real bank's API: not run.
- Sustained throughput at 50M lines/day: not measured yet.
- Evasion by a patient attacker with a valid key: not detectable by design.
