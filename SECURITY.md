# Security notes for gamai-tripwire

## Reporting

Write to renato@gamatrade.ba with the tag `[tripwire-security]`. We answer within
two working days. There is no bug bounty; we will credit you unless you ask
otherwise.

## Supported versions

| version | security fixes |
|---|---|
| 0.8.x | yes |
| < 0.8 | no |

## How releases are published

| item | value |
|---|---|
| version source | `pyproject.toml` + `tripwire/__init__.py` (both must match) |
| build | GitHub Actions `release.yml` on tag `v*` |
| upload | `pypa/gh-action-pypi-publish` with **OIDC trusted publishing** (`id-token: write`) |
| provenance | the publish step creates PEP 740 attestations (`attestations: true`) |
| scan before upload | `tools/prepublish_scan.py` refuses private keys, tokens and absolute home-directory paths |

There is **no long-lived PyPI API token** for this project. GitHub mints a
short-lived OIDC token for the tag build, PyPI verifies the publisher entry
(`gamai-io/tripwire`, workflow `release.yml`), and the attestation is attached to
the file. Verify one with:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://pypi.org/integrity/gamai-tripwire/0.8.8/gamai_tripwire-0.8.8-py3-none-any.whl/provenance
# 200
```

If a token ever appears in a workflow, treat it as a regression: the release path
is OIDC-only on purpose.

## Two-factor codes

Nobody in this project asks for a TOTP code or a seed over chat, mail or a ticket.
If someone does, it is not us. Codes are read from the owner's authenticator at
the moment of login and are never stored in the repository, the ledger or the
shared brain.

## What the tool is not allowed to claim

- Not a WAF, not inline blocking, not TLS inspection.
- No model in the decision path: a judge may explain a finding, never lower it.
- Canaries prove only that a planted token was used; they do not prove intent.
- Behaviour-only and volume-only findings alert; they never deny an address.
