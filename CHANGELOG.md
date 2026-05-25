# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **JWE foundations (Phase 3).** Structural compact serializer
  (`Jwe\CompactSerializer`) with `ParsedJwe` / `CompactJwe` DTOs — five-segment
  round-trip, fail-closed header checks (requires `alg`+`enc`, refuses `crit`
  and `zip`). Algorithm contracts `KeyManagementAlgorithm` (with
  `KeyManagementMode`) and `ContentEncryptionAlgorithm`, JWE `AlgorithmFamily`
  cases, and the `DecryptionException` leaf. No encryption crypto yet — those
  land in the following Phase 3 PRs.

### Changed

- **All RSA-based JWE deferred out of v0.3** (RSA-OAEP, RSA-OAEP-256, RSA1_5);
  see [docs/12-decisions.md](docs/12-decisions.md) (D-003). v0.3 ships the
  symmetric + ECDH-ES JWE surface, keeping zero runtime dependencies.

## [0.2.0] — 2026-05-25

Phase 2 — modern signing algorithms, explicit typing, profiles, and key
resolvers. (RSA-PSS deferred; see [docs/12-decisions.md](docs/12-decisions.md).)

### Added

- **Algorithms.** ECDSA (ES256, ES384, ES512) on OpenSSL and EdDSA
  (Ed25519) via libsodium, with point-on-curve validation on public keys.
- **Explicit typing.** `typ` enforcement at the validator, and a
  `MediaType` value object with helpers for `JWT`, `at+jwt`, `id+jwt`,
  `secevent+jwt`, and `MediaType::custom()`.
- **Profiles (Layer 6).** `AccessTokenProfile` (RFC 9068), `IdTokenProfile`
  (OpenID Connect Core 1.0), and `SetProfile` (RFC 8417). Each exposes a
  reusable `::issuer(...)` returning a fluent builder that pre-stamps the
  producer-side invariants (`typ`, `iss`, `iat`, and a random `jti` where
  the spec requires it), and a `::consumer(...)` whose `parse()` runs the
  full validator plus token-kind-specific checks: `client_id` presence for
  access tokens, `azp`/`nonce` for ID tokens, and the `events` object shape
  for SETs. Algorithm allowlists are concrete `SigningAlgorithm` objects.
- **Key resolvers.** `RemoteJwksResolver` fetches an https-only `jwks_uri`
  through an injected PSR-18 client, caches the document via PSR-16, and
  refetches once on a `kid` miss — throttled by a PSR-20 clock so
  unknown-`kid` tokens cannot trigger a fetch storm; response bodies are
  size-capped. `CompositeResolver` tries resolvers in order and falls
  through on any failure, the building block for key-rotation windows. The
  PSR HTTP/cache packages are opt-in (`suggest`); the only hard runtime
  dependency remains `psr/clock`.
- **Exception.** `InvalidClaimException` for profile-level semantic claim
  violations (e.g. `azp`/`nonce` mismatch on an ID token).
  `JwksResolutionException` for remote-JWKS transport, status, size, and
  parse failures.
- **Conformance.** RFC 7520 §4.3 ES512 (P-521) cookbook vector — the
  published signature verifies and our own ES512 signatures round-trip.
  A TLS integration test fetches a JWKS from a self-signed-CA HTTPS server
  through a real PSR-18 client, asserting both a trusted-CA success and
  that an untrusted certificate is refused (TLS verification is active).

## [0.1.0] — 2026-05-24

First usable release. Encode and decode signed JWTs with the HS and RS
algorithm families. Full BCP compliance for everything shipped.

### Added

- **Primitives.** `Base64Url`, `Json` (UTF-8 + duplicate-key rejection),
  `ConstantTime`, `Clock` (PSR-20 wrapper + `FrozenClock`), `Random`,
  `Utf8` validator.
- **Keys.** `Key` abstract; `HmacKey`, `RsaPublicKey`, `RsaPrivateKey`.
  JWK import/export per RFC 7517. `JwkSet` with `findByKid` and
  `findForAlgorithm`. `StaticJwkSetResolver`.
- **Algorithms.** HS256, HS384, HS512, RS256, RS384, RS512. `Algorithm`
  interface and `SigningAlgorithm` contract.
- **JWS (compact).** `Signer`, `Verifier`, `CompactSerializer` with
  algorithm-allowlist enforcement.
- **JWT API.** `JwtBuilder`, `JwtParser`, `ValidatorBuilder`, `Validator`,
  `UnsecuredJwtBuilder`. Full registered claims handling (`iss`, `sub`,
  `aud`, `exp`, `nbf`, `iat`, `jti`). Two-phase parse/validate API.
- **Exceptions.** Complete hierarchy under `Medzuch\Jwt\Exception`.

### Security

- Rejects `alg: none` in every shipped profile, even when a key with
  `alg = none` is present in the resolver.
- Rejects RS→HS algorithm confusion (RFC 8725 §3.1): an `RsaPublicKey`
  cannot be used to verify a token claiming an HMAC `alg`, and an
  `HmacKey` cannot be used where an RSA key is required. McLean PoC
  raises `KeyMismatchException`.
- Strict JSON parsing: duplicate keys in header or claims raise
  `MalformedTokenException`; UTF-8 validation on all decoded strings.
- Constant-time signature comparison.

### Tests

- RFC 7515 §A.1 (HS256) and §A.2 (RS256) appendix vectors reproduced
  byte-for-byte.
- RFC 7519 §3.1 example reproduced byte-for-byte.
- McLean RS→HS algorithm-confusion regression test.
- `alg: none` rejection conformance suite.

### Tooling

- PHPUnit 12 with separate `unit`, `integration`, `conformance`
  testsuites.
- PHPStan level 9 with `phpstan-strict-rules`, `phpstan-phpunit`, and
  `phpstan-deprecation-rules`; empty baseline.
- PHP-CS-Fixer with `@PER-CS2.0` + `@PHP83Migration`.
- Infection mutation testing — gate is MSI ≥ 85% overall,
  Covered-MSI ≥ 90%. Achieved: MSI 91.5%, Covered-MSI 93.5%,
  `src/Algorithm/` 97.4%, `src/Primitives/` 95.4%.
- `composer qa` (fast: CS + PHPStan + tests) and `composer qa:full`
  (adds coverage + mutation). `make` wrappers for the Docker dev
  environment.
- Docker dev image: PHP 8.3-alpine + Xdebug + libsodium + OpenSSL.

[Unreleased]: https://github.com/medzuch/jwt-php/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/medzuch/jwt-php/compare/v0.0.0...v0.1.0
