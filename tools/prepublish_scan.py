#!/usr/bin/env python3
"""Pre-publish scan: refuse to upload an artifact that leaks the build machine.

Zero dependencies. Exit 1 on anything blocking, warnings do not block.
"""
from __future__ import annotations

import re
import sys
import tarfile
import zipfile

BLOCKERS = [
    (re.compile(rb"/" + b"root/"), "absolute home path"),
    (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(rb"ghp_[A-Za-z0-9]{20,}"), "GitHub token"),
    (re.compile(rb"pypi-AgEIcHlwaS5vcmc"), "PyPI token"),
    (re.compile(rb"sk-[A-Za-z0-9]{20,}"), "API key"),
]
WARNINGS = [
    (re.compile(rb"/home/[a-z]"), "home directory path"),
    (re.compile(rb"TODO|FIXME"), "leftover TODO"),
]


def scan_bytes(name: str, blob: bytes, blocking: list, warnings: list) -> None:
    for pattern, label in BLOCKERS:
        if pattern.search(blob):
            blocking.append("%s: %s" % (name, label))
    for pattern, label in WARNINGS:
        if pattern.search(blob):
            warnings.append("%s: %s" % (name, label))
    if len(blob) > 2_000_000:
        warnings.append("%s: large member (%.1f MB)" % (name, len(blob) / 1e6))


def _skip(name: str) -> bool:
    # the scanner contains the patterns it looks for; scanning itself is noise
    return name.endswith("tools/prepublish_scan.py")


def scan(path: str, blocking: list, warnings: list) -> None:
    if path.endswith(".whl") or path.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir() or _skip(info.filename):
                    continue
                scan_bytes("%s!%s" % (path, info.filename), zf.read(info), blocking, warnings)
    elif path.endswith((".tar.gz", ".tgz")):
        with tarfile.open(path) as tf:
            for member in tf.getmembers():
                if not member.isfile() or _skip(member.name):
                    continue
                handle = tf.extractfile(member)
                if handle is not None:
                    scan_bytes("%s!%s" % (path, member.name), handle.read(), blocking, warnings)


def main(argv: list[str]) -> int:
    blocking: list[str] = []
    warnings: list[str] = []
    for path in argv[1:]:
        scan(path, blocking, warnings)
    for item in warnings:
        print("warn:", item)
    for item in blocking:
        print("BLOCK:", item)
    print("summary: %d blocking, %d warnings" % (len(blocking), len(warnings)))
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
