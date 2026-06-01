# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **JWE JSON serialization (Phase 3).** The flattened and general JWE JSON
  Serializations (RFC 7516 §7.2) alongside the existing compact form: a
  structural `Jwe\JsonSerializer` (with `Jwe\FlattenedJwe` / `Jwe\GeneralJwe`
  output types) and `Jwe\Encrypter::encryptFlattened()` / `encryptGeneral()`.
  Both add what the compact form cannot carry — a shared `unprotected` header
  and a per-recipient `header` (member names enforced disjoint across the three
  sources, §7.2.1), an explicit `aad` folded into the AAD as `Encoded Protected
  Header || '.' || BASE64URL(JWE AAD)`, and an absent protected header (AAD over
  the empty string). The effective JOSE header a recipient acts on is the union
  of all three sources, while only the protected header feeds the AAD; the
  `Jwe\Decrypter` consumes the resulting `ParsedJwe` unchanged. Conformance: the
  RFC 7516 §A.3 (`A128KW`) and RFC 7520 §5.4 (`ECDH-ES+A128KW`) vectors decrypt
  identically when recomposed into both JSON syntaxes. Multiple recipients (a
  `recipients` array longer than one) are refused on parse and deferred to a
  later PR; production emits a single recipient.
- **JWE ECDH-ES key agreement (Phase 3).** Key-management algorithms `ECDH-ES`
  (Direct Key Agreement) and `ECDH-ES+A128KW` / `+A192KW` / `+A256KW` (Key
  Agreement with Key Wrapping) on the NIST curves P-256/P-384/P-521 (RFC 7518
  §4.6), built on `openssl_pkey_derive` + the Concat KDF (NIST SP 800-56A,
  SHA-256), zero new runtime dependencies. The ephemeral `epk` is validated
  on-curve and required to match the recipient key's curve, defeating the
  invalid-curve attack (Sanso). `EcKey`/`EcCurve` now accept EC keys bound to
  the ECDH-ES algorithms on any supported curve (the ECDSA crv↔alg pairing is
  unchanged). Conformance: RFC 7518 Appendix C (agreement → derived key,
  including `apu`/`apv`) and RFC 7520 §5.4 (`ECDH-ES+A128KW` full token
  decrypt). Note: the encryption path uses empty `apu`/`apv` and rejects a
  caller-supplied one (it would desync the recipient's KDF); the decryption
  path honours any present, so it interoperates with senders that set them.
  X25519 (OKP) ECDH-ES is deferred to a later release.
- **JWE AES key wrapping (Phase 3).** Key-management algorithms `A128KW` /
  `A192KW` / `A256KW` (AES Key Wrap, RFC 7518 §4.4, via OpenSSL's `aes-*-wrap`
  with the RFC 3394 default IV) and `A128GCMKW` / `A192GCMKW` / `A256GCMKW`
  (AES-GCM Key Wrap, RFC 7518 §4.7, carrying the per-recipient `iv` / `tag`
  header parameters). Each wraps a fresh random Content Encryption Key under an
  `OctKey` Key Encryption Key bound to the wrapping `alg`. Conformance: RFC 7516
  Appendix A.3 (`A128KW` + `A128CBC-HS256`) decrypts end-to-end to the published
  plaintext. Still zero runtime dependencies.
- **JWE content encryption + `dir` (Phase 3).** Content-encryption algorithms
  `A128GCM`/`A192GCM`/`A256GCM` and `A128CBC-HS256`/`A192CBC-HS384`/
  `A256CBC-HS512` (RFC 7518 §5), the `dir` (Direct Encryption) key-management
  algorithm, an `OctKey` symmetric key for JWE, and the `Jwe\Encrypter` /
  `Jwe\Decrypter` (allowlist-driven, compact serialization). The
  `KeyManagementAlgorithm` contract gained uniform `encryptKey()` / `decryptKey()`
  operations (via `CekEncryptionResult`). Conformance: RFC 7518 Appendix B
  AES-CBC-HMAC vectors reproduce byte-for-byte.
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
