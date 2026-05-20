# Contributing

Thanks for your interest in contributing. This library is security-sensitive,
so the bar for contributions is high. Read this in full before opening a PR.

## Ground rules

1. **No new public API without an RFC reference.** Either an IETF RFC, a JOSE
   draft, or an OAuth/OIDC spec section. The reference goes in the PR
   description.
2. **No reduction of safety defaults.** Adding an opt-in flag for an
   intentionally unsafe behaviour (e.g. `b64:false`, `jku` fetching) is fine if
   it requires explicit caller action. Quietly changing a default is not.
3. **Every crypto-adjacent change ships with tests** — preferably RFC test
   vectors. Mutation-testing MSI on `src/Algorithm/` and `src/Jws/` must not
   decrease.
4. **PHPStan level 9 stays green.** No baseline entries without a written
   explanation and a follow-up issue.
5. **No new direct dependencies without discussion.** Especially anything
   touching crypto, HTTP, or parsing.

## Workflow

1. Open an issue first for non-trivial changes.
2. Fork, branch from `develop`.
3. Develop in the Docker dev container (`make sh`).
4. Run `make qa` before pushing. Mutation testing (`make qa-full`) is run by CI.
5. Open the PR against `develop`. Reference the issue and the RFC section(s).

## Commit messages

Conventional Commits format:

```
feat(jws): add ES256K signing algorithm
fix(parser): reject duplicate claim names per RFC 7519 §4
docs(threat-model): clarify jku/x5u rationale
test(conformance): add RFC 7520 §4.4 vectors
```

## Code style

`composer cs:fix` before pushing. See [docs/08-coding-standards.md](docs/08-coding-standards.md).

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not open a public issue.
