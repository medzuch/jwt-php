# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
