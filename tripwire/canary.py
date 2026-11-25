"""Canary tokens: keys that should never be used, and the alarm when one is.

A canary is a credential-shaped string planted where only a scanner, a confused
agent or an intruder reading our own docs would find it. Any use is a
high-signal event: no legitimate client has a reason to send it.

The registry stores the SHA-256 of each token, never the token itself, so a
leaked registry does not hand an attacker the strings that trip the alarm.
Tokens are printed once, at generation time; after that they cannot be
recovered, only revoked.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time

PREFIX = "tw_"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _write(path: str, data: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)


class RegistryError(Exception):
    """The registry exists but cannot be used. Never treat this as 'no canaries'."""


def load(path: str = "canaries.json", strict: bool = False) -> dict:
    if not os.path.exists(path):
        return {"version": 1, "canaries": []}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except ValueError as exc:
        if strict:
            raise RegistryError("%s is not valid JSON: %s" % (path, exc)) from exc
        return {"version": 1, "canaries": []}
    if not isinstance(data, dict) or not isinstance(data.get("canaries"), list):
        if strict:
            raise RegistryError("%s has no canaries list" % path)
        return {"version": 1, "canaries": []}
    for item in data["canaries"]:
        if not isinstance(item, dict) or "sha256" not in item:
            if strict:
                raise RegistryError("%s has a malformed entry" % path)
    return data


def generate(count: int = 3, note: str = "", path: str = "canaries.json",
             registry: dict | None = None) -> dict:
    """Add `count` canaries to the registry and return the plaintext tokens once."""
    data = registry if registry is not None else load(path)
    items = list(data.get("canaries") or [])
    tokens = []
    for _ in range(max(1, int(count))):
        token = PREFIX + secrets.token_urlsafe(24)
        tokens.append(token)
        items.append({"id": secrets.token_hex(6), "sha256": _hash(token),
                      "note": note, "created": int(time.time()),
                      "revoked": False})
    data = {"version": 1, "canaries": items}
    _write(path, data)
    return {"path": path, "tokens": tokens, "count": len(items)}


def match(text: str, registry: dict | None) -> list[dict]:
    """Return the registry entries whose hash appears in `text`."""
    if not text or not registry:
        return []
    known = {c.get("sha256"): c for c in (registry.get("canaries") or [])
             if isinstance(c, dict) and not c.get("revoked")}
    if not known:
        return []
    hits = []
    for candidate in candidates(text):
        entry = known.get(_hash(candidate))
        if entry is not None:
            hits.append(entry)
    return hits


def candidates(text: str) -> list[str]:
    """Every substring shaped like a canary token."""
    out = []
    index = 0
    while True:
        index = text.find(PREFIX, index)
        if index < 0:
            return out
        end = index + len(PREFIX)
        while end < len(text) and (text[end].isalnum() or text[end] in "-_"):
            end += 1
        out.append(text[index:end])
        index = end


def revoke(canary_id: str, path: str = "canaries.json") -> dict:
    data = load(path)
    found = 0
    for entry in data.get("canaries") or []:
        if entry.get("id") == canary_id:
            entry["revoked"] = True
            found += 1
    _write(path, data)
    return {"revoked": found, "id": canary_id}
