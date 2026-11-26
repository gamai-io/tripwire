#!/usr/bin/env python3
"""Keep the version and the numbers in the README true.

    python3 tools/claims.py --check     # CI gate
    python3 tools/claims.py --write     # regenerate CLAIMS.md
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def version() -> str:
    text = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    match = re.search(r'^version = "(?P<v>[^"]+)"', text, re.M)
    if not match:
        raise SystemExit("pyproject.toml has no version")
    return match.group("v")


def module_version() -> str:
    out = subprocess.run([sys.executable, "-c",
                          "import tripwire; print(tripwire.__version__)"],
                         cwd=ROOT, capture_output=True, text=True)
    return out.stdout.strip() or "unknown"


def _passed() -> int:
    out = subprocess.run([sys.executable, "-m", "pytest", "-q", "tests/"], cwd=ROOT,
                         capture_output=True, text=True)
    match = re.search(r"(\d+) passed", out.stdout + out.stderr)
    return int(match.group(1)) if match else -1


def count_tests() -> int:
    out = subprocess.run([sys.executable, "-m", "pytest", "-q", "--collect-only",
                          "tests/"], cwd=ROOT, capture_output=True, text=True)
    match = re.search(r"(\d+) tests? collected", out.stdout + out.stderr)
    return int(match.group(1)) if match else -1


def _measure() -> dict | None:
    """Run the corpus and return the numbers, so the claims file cannot drift."""
    import tempfile
    directory = tempfile.mkdtemp(prefix="claims-")
    try:
        subprocess.run([sys.executable, "tools/gen_corpus.py", "--out", directory,
                        "--benign", "360", "--attack", "80"], cwd=ROOT, check=True,
                       capture_output=True)
        done = subprocess.run([sys.executable, "tools/measure.py", "--corpus", directory],
                              cwd=ROOT, check=True, capture_output=True, text=True)
        return json.loads(done.stdout)
    except Exception:                       # noqa: BLE001
        return None


def measured_rows() -> list[str]:
    data = _measure()
    if not data:
        return ["| corpus | unmeasured | `python3 tools/measure.py --corpus corpus` |"]
    return [
        "| benign sessions flagged | %d / %d | `python3 tools/gen_corpus.py --out corpus --benign 360 --attack 80 && python3 tools/measure.py --corpus corpus` |"
        % (data["benign_medium_or_higher"], data["benign_sessions"]),
        "| attacks at high | %d / %d | same command |"
        % (data["attack_detected_high"], data["attack_sessions"]),
        "| attacks at medium+ | %d / %d | same command |"
        % (data["attack_detected_any"], data["attack_sessions"]),
    ]


def check() -> list[str]:
    current, problems = version(), []
    if os.path.exists(os.path.join(ROOT, "SECURITY.md")):
        security = open(os.path.join(ROOT, "SECURITY.md"), encoding="utf-8").read()
        line = ".".join(current.split(".")[:2]) + ".x"
        row = re.search(r"\|\s*([0-9]+\.[0-9]+\.x)\s*\|\s*yes\s*\|", security)
        if not row:
            problems.append("SECURITY.md has no supported-version table")
        elif row.group(1) != line:
            problems.append("SECURITY.md supports %s, pyproject is %s"
                            % (row.group(1), current))
    if module_version() != current:
        problems.append("tripwire.__version__ %s != pyproject %s"
                        % (module_version(), current))
    changelog = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
    first = re.search(r"^## (\d+\.\d+\.\d+)", changelog, re.M)
    if not first:
        problems.append("CHANGELOG.md has no release section")
    elif first.group(1) != current:
        problems.append("CHANGELOG.md newest section is %s, pyproject is %s"
                        % (first.group(1), current))
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    if not re.search(r"\d+\s+tests?", readme):
        problems.append("README.md states no test count; a silent pass is not a claim")
    for match in re.finditer(r"(?P<n>\d+) tests", readme):
        if int(match.group("n")) != _passed():
            problems.append("README claims %s tests, suite has %d passing"
                            % (match.group("n"), _passed()))
    # CLAIMS.md is the evidence index; a stale number there lies with authority
    claims_path = os.path.join(ROOT, "CLAIMS.md")
    if os.path.exists(claims_path):
        claims = open(claims_path, encoding="utf-8").read()
        version_row = re.search(r"\| version \| ([0-9.]+) \|", claims)
        if version_row and version_row.group(1) != current:
            problems.append("CLAIMS.md says version %s, pyproject is %s"
                            % (version_row.group(1), current))
        for label, actual in (("tests collected", count_tests()),
                              ("tests passing", _passed())):
            row = re.search(r"\| %s \| (\d+) \|" % re.escape(label), claims)
            if row and int(row.group(1)) != actual:
                problems.append("CLAIMS.md says %s %s, suite has %d"
                                % (label, row.group(1), actual))
        measured = _measure()
        if measured:
            for label, pattern, expected in (
                    ("benign sessions flagged",
                     r"\| benign sessions flagged \| (\d+) / (\d+) \|",
                     (measured["benign_medium_or_higher"], measured["benign_sessions"])),
                    ("attacks at high",
                     r"\| attacks at high \| (\d+) / (\d+) \|",
                     (measured["attack_detected_high"], measured["attack_sessions"])),
                    ("attacks at medium+",
                     r"\| attacks at medium\+ \| (\d+) / (\d+) \|",
                     (measured["attack_detected_any"], measured["attack_sessions"]))):
                row = re.search(pattern, claims)
                if not row:
                    problems.append("CLAIMS.md has no '%s' row" % label)
                    continue
                got = (int(row.group(1)), int(row.group(2)))
                if got != expected:
                    problems.append("CLAIMS.md says %s %s, corpus measured %s"
                                    % (label, got, expected))
    return problems


def write_claims() -> str:
    text = "\n".join([
        "# Claims and how to check them", "",
        "| claim | value | command |", "|---|---|---|",
        "| version | %s | `python3 tools/claims.py --version` |" % version(),
        "| tests collected | %d | `python3 -m pytest -q --collect-only tests/` |"
        % count_tests(),
        "| tests passing | %d | `python3 -m pytest -q tests/` |" % _passed(),
        *measured_rows(),
        "", "## Not proven here", "",
        "- Detection inside a real bank's API: not run.",
        "- Sustained throughput at 50M lines/day: not measured yet.",
        "- Evasion by a patient attacker with a valid key: not detectable by design.",
        ""])
    with open(os.path.join(ROOT, "CLAIMS.md"), "w", encoding="utf-8") as fh:
        fh.write(text)
    return text


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--version", action="store_true")
    args = ap.parse_args()
    if args.version:
        print(version())
        return 0
    if args.write:
        print(write_claims())
        return 0
    problems = check()
    for problem in problems:
        print("DRIFT:", problem)
    if problems:
        print("\n%d claim(s) disagree with the code." % len(problems))
        return 1
    print("claims consistent: %s, %d tests" % (version(), count_tests()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
