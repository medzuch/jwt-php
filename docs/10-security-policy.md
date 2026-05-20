# 10 — Security Policy

This is the in-depth complement to the top-level [`SECURITY.md`](../SECURITY.md).
The top-level file is the disclosure policy. This file describes how the
project operates day-to-day to *avoid* having vulnerabilities to disclose.

## Threat-model-driven development

Every PR that touches `src/Algorithm/`, `src/Jws/`, `src/Jwe/`, or
`src/Key/` must:

1. Reference the relevant RFC section(s) in the PR description.
2. Include or reference a regression test, especially if the PR is a fix.
3. Not reduce mutation MSI on the affected files.
4. Be reviewed by at least one person who did not write the change.

## Dependencies

- `roave/security-advisories` is in `require-dev` and locks Composer to
  refuse installing any package with a known advisory.
- Direct runtime dependencies are kept minimal. Adding one requires a
  written rationale in the PR.
- Composer is run with `--prefer-dist` in CI to use signed tarballs from
  Packagist rather than `git clone` from arbitrary repositories.

Current runtime dependencies and the reason each is acceptable:

| Package | Reason |
|---------|--------|
| `psr/clock` | Stable PSR interface; zero code. |
| `psr/log` | Stable PSR interface; zero code. |
| `psr/simple-cache` | Stable PSR interface; zero code. |
| `psr/http-client`, `psr/http-factory` | Stable PSR interfaces; zero code. |

Constant-time base64url encoding is provided by PHP core via
`sodium_bin2base64` / `sodium_base642bin` with the
`SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING` variant. We do not pull in a
userland constant-time encoding library because `ext-sodium` is already a
hard requirement for Ed25519/X25519 support.

No HTTP client implementation is required at runtime — the consumer
brings their own. The dev dependency on `symfony/http-client` is for
testing the JWKS resolver only.

## Reproducible builds

`composer.lock` is committed for the **dev environment** but excluded
from `dist` exports for library consumers (libraries don't ship locks).
The lock anchors the toolchain so that `make qa` produces identical
results in CI and locally.

## CI hardening

The GitHub Actions workflow:

- Uses pinned action versions (`@v4`, not `@latest`).
- Runs with the minimum permissions (`contents: read`).
- Caches Composer between runs but never trusts the cache for security —
  each install re-validates dependency hashes.
- Uses `concurrency` to cancel superseded runs, preventing race conditions
  in deploy/release workflows.

In Phase 5 we will add:

- StepSecurity Harden-Runner for outbound network monitoring.
- SLSA Level 2 provenance attestation on releases.
- Sigstore-signed release tarballs.

## Release process

1. All CI green on `develop`.
2. Mutation testing run with `composer qa:full` passes locally.
3. CHANGELOG.md updated.
4. Version bump in `Medzuch\Jwt\Version::SEMVER`.
5. Tag with `git tag -s vX.Y.Z` (signed tag, mandatory).
6. Push tag; CI workflow attaches build artefacts to the GitHub release.

Tags without GPG signatures will not be published to Packagist.

## Secret handling in tests

Tests use **deterministic** keys (from RFC test vectors) wherever
possible. When a test needs a fresh key, it is generated at runtime via
`random_bytes` / `openssl_pkey_new` and discarded at the end of the test
process.

No real key material is ever committed. A pre-commit hook (Phase 5) will
run `trufflehog` against staged files.

## Cryptographic agility

The library is designed to deprecate algorithms over time. Each algorithm
class can carry a `deprecated_since` and `removed_in` constant. The
validator emits PSR-3 warnings when a deprecated algorithm is accepted.

Algorithms scheduled for early deprecation:

- **RSA1_5** — encrypt path is already disabled. Decrypt path will be
  marked deprecated in v1.1 and removed in v2.0.
- **HS***  with weak keys — already enforced at construction.

## Out-of-band changes

If a CVE is published in a dependency mid-cycle:

1. Open a private security advisory in the repo.
2. Bump the dependency, run `qa:full`.
3. Cut a patch release on the affected version(s).
4. Backport to supported branches.
5. Publish the advisory once the patches are tagged.

## Audit trail

The project maintains a security log at `docs/security-log.md` (created
when needed) listing:

- Date of each material security-relevant change.
- Linked PR, issue, advisory.
- Algorithm/feature affected.
- Reviewer.

This is for traceability, not blame.
