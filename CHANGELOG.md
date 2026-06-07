# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Custom PHPStan rule for timing side-channels (Phase 5, threat-model T12).**
  A project rule (`Medzuch\Jwt\PHPStan\ConstantTimeComparisonRule`, in
  `tooling/phpstan/`) flags any variable-time `===`/`!==`/`==`/`!=` comparison of
  byte values named like signature/MAC/tag material and directs them to
  `ConstantTime::equals()` / `hash_equals()`. It runs as part of the level-9
  analysis (`make phpstan`) and is a regression guard — the library already
  routes every such comparison through constant time. Low-noise by design
  (skips presence/length/sentinel checks); the one structural ASN.1 DER tag byte
  is whitelisted with a documented `ignoreErrors` entry. Covered by a
  `RuleTestCase` test.
- **Optional PSR-3 logging hooks (Phase 5).** Every consume-side entry point —
  `Validator` (via `ValidatorBuilder::withLogger()`), the standalone JWS
  `Verifier`, the JWE `Decrypter`, the RFC 9068/OIDC/RFC 8417 profile consumers
  (via their `consumer()` factories), the `NestedJwtParser` (which threads the
  logger to its inner `Decrypter`/`Verifier`), and the `RemoteJwksResolver` — now
  accepts an optional `Psr\Log\LoggerInterface` and emits one redacted diagnostic
  event per outcome: token accepted, signature/verification failure, claim
  rejection (naming the failing claim), JWE decryption success/failure, and JWKS
  resolution (cache/network/failure). The new `Medzuch\Jwt\Diagnostics\LogLevels`
  value object remaps which PSR-3 level each event category is emitted at
  (secure defaults: accepted/decrypted/cache at `debug`, claim rejections at
  `notice`, integrity failures at `warning`). **Redaction is enforced in one place:** only
  `kid`, `alg`, `enc`, `typ`, `profile`, the failing claim *name*, the `reason`
  (exception short-class), and the configured `jwks_uri`/cache source are ever
  logged — never tokens, payloads, claim values, key material, or exception
  messages. Logging is entirely opt-in; without a logger no diagnostics code
  runs and `psr/log` is not required.
- **Property-based parser tests (Phase 5).** A new `property` test suite
  (`tests/Property/`) asserts the same contract as the fuzzer — only a
  `JwtException` may escape a parser fed arbitrary bytes — across all seven
  untrusted-input entry points (`JwtParser::parse`, `Json::decode`,
  `Base64Url::decode`, and the JWS/JWE compact and JSON deserializers). Inputs
  come from a deterministic, structure-aware `HostileInputGenerator` (seeded via
  a private xorshift PRNG), so the suite runs on every `make test` and replays
  failures exactly; set `JWT_PROPERTY_SEED` to widen the explored space. This is
  the fast, always-on complement to the wall-clock-bounded nightly fuzzer. Run
  with `composer test:property`.
- **Fuzzing harness (Phase 5).** Coverage-guided fuzz targets
  (`nikic/php-fuzzer`) for the untrusted-input parsers — `JwtParser::parse`,
  `Json::decode`, `Base64Url::decode`, and the JWS/JWE compact deserializers —
  under `tests/Fuzz/`. Each target asserts that only a `JwtException` may
  escape; any other `Throwable` (`Error`/`TypeError`/`ValueError`/
  `JsonException`/SPL) is a crash. A nightly GitHub Actions workflow
  (`.github/workflows/fuzz.yml`) runs every target time-boxed with a cached
  corpus and auto-files de-duplicated **P0** issues on a crash. Run locally
  with `make fuzz TARGET=<name> RUNS=<n>`.

### Changed

- **`Profile\ProfileConsumer::__construct()` gained a required `string $profileName`
  parameter** (after `$validator`), so the consumer can label its redacted log
  events. All shipped profile consumers pass it; this only affects external code
  that subclasses `ProfileConsumer` directly — a pre-1.0 break called out ahead of
  the API freeze.
- **Mutation testing hardened (Phase 5, RFC-roadmap §5).** The Infection gate is
  now **Covered-code MSI ≥ 95** as the real quality bar, with a deliberately
  loose **overall MSI ≥ 85** backstop on testing breadth (was 85 / 90). Actual
  scores are **~94% MSI / ~97% covered** across `src/`, with `src/Algorithm/`
  and `src/Jws/` at **≥ 99%** (most at 100%). The work was test-quality, not
  behaviour change: added boundary and error-path tests (notably the `Validator`
  `exp`/`nbf`/`iat` leeway-boundary cases, the ASN.1 DER codec edges, RSA
  minimum-key-size and algorithm-family rejection, the JWS/JWE header-shape
  validators, and the JWS JSON-serialization paths), plus dedicated
  `#[CoversClass]` test classes for internal helpers whose coverage was
  previously only incidental.
- Exception constructors that passed an explicit `0` code now use the named
  `previous:` argument (`new XException($msg, previous: $e)`), eliminating a
  class of equivalent mutants with no behavioural change.
- Unreachable defensive guards (OpenSSL backend-failure paths, etc.) rely on
  `@codeCoverageIgnore` alone — which excludes them from coverage and from
  Covered MSI — rather than `@infection-ignore-all`. The latter is now reserved
  for genuinely-equivalent mutants on *covered* code (error-queue hygiene,
  diagnostic message helpers, opaque cache-key construction), each annotated
  with a concrete rationale. The two visibility mutators (uncoverable by
  construction) remain disabled in `infection.json5`.
- Added a `make test-mutation` target (Infection with a 512M memory limit).

## [0.4.0] — 2026-06-02

Phase 4 — RFC 7797 `b64:false` and detached payloads at the JWS layer, and
JWS JSON Serialization in both flattened (RFC 7515 §7.2.2) and general
(§7.2.1, multi-signature) syntaxes. Multi-signature is real: one shared
payload signed under N (algorithm, key) pairs, each signature verified
independently by the existing single-signature `Jws\Verifier`. The JWT
layer keeps refusing `b64` outright (RFC 7797 §7) and keeps refusing the
JSON serializations (RFC 7519 §7) — both are JWS-layer features by
construction.

### Added

- **JWS JSON Serialization (Phase 4).** The flattened (RFC 7515 §7.2.2) and
  general (RFC 7515 §7.2.1) JSON syntaxes alongside the existing compact
  form. `Jws\Signer` gained `signFlattened()` for the single-signature
  case and `signGeneral(SignatureSpec[], $payload)` for multi-signature —
  one shared payload signed under any number of (algorithm, key) pairs,
  the canonical use being a JWS for multiple recipients with different
  algorithm preferences. Structural `Jws\JsonSerializer` (with
  `Jws\FlattenedJws` / `Jws\GeneralJws` output types and a
  `Jws\ParsedJsonJws` aggregate view) is the JSON counterpart to the
  compact serializer; each parsed signature is a self-contained
  `Jws\ParsedJws` that the existing single-signature
  `Jws\Verifier::verify()` consumes unchanged. Enforces RFC 7515 §7.2.1
  protected/unprotected header disjointness per signature, refuses a
  JWS that mixes the general `signatures` array with the flattened
  top-level fields, and refuses multi-signature JWS where `b64` disagrees
  across signatures (RFC 7797 §5.2). Detached payload (RFC 7515 Appendix F)
  travels as a missing `payload` member and rejoins via
  `Jws\Verifier::verifyDetached()`. The JWT layer continues to refuse the
  JSON serializations — only compact JWT is valid (RFC 7519 §7).
- **RFC 7797 `b64:false` JWS support (Phase 4).** The JWS layer now accepts
  the `b64` header parameter at parse, sign, and verify. Setting `b64: false`
  (with `crit: ["b64"]` per RFC 7797 §6) on `Jws\Signer::sign()` produces a
  compact form whose middle segment is the raw payload bytes rather than
  base64url-encoded; the signing input becomes
  `ASCII(BASE64URL(header) || '.' || payload)` per §3. `Jws\Verifier::verify()`
  honours the same flag and refuses a header that declares `b64:false`
  without `crit` listing `"b64"` (defence in depth — `Jws\CompactSerializer`
  refuses it too on parse). The JWT layer continues to refuse `b64` outright
  per RFC 7797 §7 (T14 mitigation unchanged); the `JwtBuilder` reserved-headers
  list already blocked it, and `JwtParser` rejects any inbound JWT whose
  header carries `b64`.
- **Detached payload helpers (RFC 7515 Appendix F).** `Jws\Signer::sign()`
  gained a `$detached` flag — when true the compact form emits an empty
  middle segment and the payload travels out of band. `Jws\Verifier::verifyDetached()`
  is the consumer counterpart: it takes the external payload, reconstructs
  the signing input honouring the `b64` mode, and verifies. The two flavours
  enforce a wrong-shape boundary check (detached → `verifyDetached()`,
  non-detached → `verify()`) so callers who confuse them get a typed
  exception rather than a silent wrong-signing-input verification.
- **`crit:["b64"]` extension processing.** Both the structural serializer
  and the verifier accept `crit` when it lists the `"b64"` extension and
  refuse it with a typed message when it lists anything else (RFC 7515
  §4.1.11 — Phase 4 understands only `b64`). The pre-Phase-4 blanket
  refusal of any `crit` is therefore relaxed for that one entry only.
- **Conformance.** RFC 7797 §A.1 (HS256, payload `$.02` containing `.`)
  verifies under the published key, and `Jws\Signer` reproduces the
  published token byte-exact.

### Security

- **JSON-parse alg-in-protected enforcement.** `Jws\JsonSerializer::deserialize()`
  refuses a JWS whose protected header is missing `alg` (or whose `alg`
  rides only in the unauthenticated `header` member): algorithm selection
  must be driven by an integrity-protected value (RFC 7515 §4.1.1, RFC 8725
  §3.1). The `alg` / `typ` / `cty` / `kid` shape checks now live in a shared
  `Jws\Internal\HeaderShape` helper invoked by both the compact and JSON
  parse paths — single source of truth, so a token one path produces is
  parseable by the other and the two ends cannot drift.

## [0.3.0] — 2026-06-01

Phase 3 — JWE encryption: symmetric (`A*KW`/`A*GCMKW`/`dir`) and ECDH-ES key
management, AES-GCM and AES-CBC-HMAC content encryption, both compact and
flattened/general JSON serializations, and nested JWTs (sign-then-encrypt
with `cty` and RFC 7519 §5.3 replicated-claim enforcement). All RSA-based
key management explicitly deferred — see
[docs/12-decisions.md](docs/12-decisions.md) (D-003).

### Added

- **`MediaType::equivalent()`.** Promoted the wire-level media-type
  comparison out of `Validator` so the JWS-side `typ` check and the
  JWE-side `cty` check (nested JWT) share one normaliser (case-insensitive,
  `application/` prefix optional, RFC 7515 §4.1.9).
- **Nested JWT (Phase 3).** `Jwt\NestedJwtBuilder::wrap()` takes an already
  signed `CompactJws` and wraps it as a `CompactJwe` — the sign-then-encrypt
  order RFC 7519 §11.2 recommends, encoded in the type so the producer cannot
  encrypt unsigned plaintext through this entry point (T4). The outer header
  is auto-stamped with `cty: "JWT"` per RFC 7519 §5.2 and refuses any other
  value. `Jwt\NestedJwtParser::parse()` is the consumer counterpart: sniffs
  compact vs. JSON outer serialization, runs `Jwe\Decrypter` under the
  caller's `alg`/`enc` allowlist, requires `cty: "JWT"` on the decrypted
  outer header, parses + verifies the inner JWS under the caller's signing
  allowlist, and enforces RFC 7519 §5.3 — claim names present in both the
  outer JOSE header and the inner Claims Set must hold equal values
  (intersection equality, mismatch raises `InvalidHeaderException`). Returns
  a `NestedJwt` aggregate the caller can hand to `Validator` exactly like a
  `ParsedJwt`. Roundtrip exit criterion (RFC 8725 §3.11 closing paragraph)
  exercised across `dir`+`A256GCM` and `A128KW`+`A128CBC-HS256` plus
  flattened-JSON outer serialization.
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

### Security

- **Threat model T16** — `docs/02-threat-model.md` now documents the JSON
  serialization's unauthenticated `unprotected` / per-recipient `header`
  surface: which JOSE parameters may legitimately ride there, what the
  practical residual is (collapses to `DecryptionException`, not plaintext
  disclosure, via allowlist-driven decrypt + per-key algorithm binding +
  AEAD content tag), and how to obtain a compact-path-equivalent "by
  construction" guarantee when application policy requires it.

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

[Unreleased]: https://github.com/medzuch/jwt-php/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/medzuch/jwt-php/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/medzuch/jwt-php/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/medzuch/jwt-php/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/medzuch/jwt-php/compare/v0.0.0...v0.1.0
