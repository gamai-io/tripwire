# Security notes for gamai-tripwire

## Reporting

Write to renato@gamatrade.ba with the tag `[tripwire-security]`. We answer within
two working days. There is no bug bounty; we will credit you unless you ask
otherwise.

## How releases are published

| item | value |
|---|---|
| version source | `pyproject.toml` + `tripwire/__init__.py` (both must match) |
| build | GitHub Actions `release.yml` on tag `v*` |
| upload | `pypa/gh-action-pypi-publish` with `secrets.PYPI_API_TOKEN` |
| provenance | `attest.yml` runs `actions/attest-build-provenance` on the same tag |
| scan before upload | `tools/prepublish_scan.py` refuses private keys, tokens, `/root/` paths |

The token is a long-lived PyPI API token scoped to this project, held only as a
GitHub Actions secret. It is never printed, never written into the repo, and
never used interactively.

### Rotating the token

1. PyPI -> Account settings -> API tokens -> revoke the old token for this project.
2. Create a new project-scoped token for `gamai-tripwire`.
3. `gh secret set PYPI_API_TOKEN -R gamai-io/tripwire` (paste when prompted; do not pass it on a command line that lands in shell history).
4. Push a tag to prove it: the `release` run must reach the `publish` job.
5. `gh secret list -R gamai-io/tripwire` shows only the update timestamp, never the value.

### Optional: drop the token entirely

PyPI supports OIDC trusted publishing. After adding the publisher entry
(project `gamai-tripwire`, owner `gamai-io`, repository `tripwire`, workflow
`release.yml`, environment empty), set `permissions: id-token: write` in
`release.yml`, remove the `password:` line and delete the secret. Until that
entry exists, the token is the working path and is documented above rather than
hidden.

## Two-factor codes

Nobody in this project asks for a TOTP code or a seed over chat, mail or a ticket.
If someone does, it is not us. Codes are read from the owner's authenticator at
the moment of login and are never stored in the repository, the ledger or the
shared brain.

## What the tool is not allowed to claim

- Not a WAF, not inline blocking, not TLS inspection.
- No model in the decision path: a judge may explain a finding, never lower it.
- Canaries prove only that a planted token was used; they do not prove intent.
