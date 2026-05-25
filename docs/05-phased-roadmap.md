# 05 — Phased Roadmap

Five implementation phases, each shippable as a minor version. The rough
estimate is two weeks per phase for a solo developer; less with a pair.
Each phase has explicit entry and exit criteria so that "done" is not a
matter of taste.

## Phase 1 — Foundations & HS/RS JWS (target: v0.1)

**Goal.** Encode and decode signed JWTs with the two most common algorithm
families. Full BCP compliance for everything that is implemented.

### Deliverables

- **Layer 1 (Primitives).**
  - `Base64Url`, `Json` (UTF-8 + duplicate-key rejection), `ConstantTime`,
    `Clock` (PSR-20 wrapper + `FrozenClock`), `Random`, `Utf8` validator.
- **Layer 2 (Keys).**
  - `Key` abstract; `HmacKey`, `RsaPublicKey`, `RsaPrivateKey`.
  - JWK import/export per RFC 7517.
  - `JwkSet` with `findByKid` and `findForAlgorithm`.
  - `StaticJwkSetResolver`.
- **Layer 3 (Algorithms).**
  - HS256, HS384, HS512.
  - RS256, RS384, RS512.
  - `Algorithm` interface and `SigningAlgorithm` contract.
- **Layer 4 (JWS, compact only).**
  - `Signer`, `Verifier`, `CompactSerializer`.
  - Algorithm-allowlist enforcement.
- **Layer 5 (JWT API).**
  - `JwtBuilder`, `JwtParser`, `ValidatorBuilder`, `Validator`.
  - Full registered claims handling: `iss`, `sub`, `aud`, `exp`, `nbf`,
    `iat`, `jti`.
  - Two-phase parse/validate API.
- **Exceptions.** Full hierarchy from [01-architecture](01-architecture.md).
- **Docs.** README, threat model, this roadmap, RFC compliance matrix.
- **Tests.** RFC 7515 Appendix A.1–A.2 conformance, RFC 7519 §3.1
  conformance, algorithm-confusion regression tests.

### Exit criteria

1. RFC 7515 §A.1 (HS256) and §A.2 (RS256) test vectors pass.
2. RFC 7519 §3.1 example reproduces byte-for-byte.
3. McLean RS→HS confusion PoC throws `KeyMismatchException`.
4. `alg:none` token is rejected by every shipped profile, even when a key
   with `alg = none` would happen to be in the key set.
5. PHPStan level 9 green, no baseline entries.
6. PHPUnit code coverage on `src/` ≥ 95%.
7. Mutation MSI on `src/Algorithm/` and `src/Primitives/` ≥ 90%.

### Out of scope this phase

- ECDSA, EdDSA, RSA-PSS.
- JWE.
- JWS JSON serialization.
- `b64:false` (RFC 7797).
- Remote JWKS fetching.
- Explicit typing (`typ`) enforcement — added in Phase 2.

## Phase 2 — Modern signing & explicit typing (target: v0.2)

**Goal.** Cover the rest of the signing algorithms, ship explicit-typing
support, and provide pre-baked profiles.

### Deliverables

- ES256, ES384, ES512 (ECDSA). OpenSSL backend with RFC 6979 deterministic
  mode where available; explicit point-on-curve validation on public keys.
- EdDSA (Ed25519) via libsodium.
- `typ` header enforcement at validator and profile level.
- Registered media-type helpers: `at+jwt`, `id+jwt`, `secevent+jwt`, plus
  a `MediaType::custom(string $name): MediaType` for application-defined
  types.
- **Layer 6 (Profiles).**
  - `AccessTokenProfile` (RFC 9068 posture).
  - `IdTokenProfile` (OIDC Core 1.0 posture).
  - `SetProfile` (RFC 8417).
- **Key resolvers.**
  - `RemoteJwksResolver` (PSR-18 + PSR-16 + PSR-20, hard timeouts).
  - `CompositeResolver` for rotation windows.
- Key rotation tests (overlapping `kid` windows).

### Exit criteria

1. RFC 7520 cookbook signing vectors pass for the algorithms shipped
   (ES*, EdDSA — RS* already proven in Phase 1; PS* deferred, see below).
2. Invalid-curve regression test (T6) passes.
3. Each profile's required-claims test matrix is green.
4. Remote JWKS fetcher has explicit TLS-enabled integration test using a
   self-signed CA fixture.

### Deferred out of Phase 2

- **RSA-PSS (PS256, PS384, PS512).** PHP 8.3 + OpenSSL 3.x does not expose
  PSS via `openssl_sign`, leaving only two paths: ship a hand-rolled
  EMSA-PSS implementation (~250 LoC of crypto we'd own and audit
  forever) or pull in `phpseclib/phpseclib` and pivot the library's
  *"standalone, zero-runtime-deps"* positioning. Neither is right for
  v0.2. Tracked for a later release as either an opt-in dependency
  inside this library or a separate `medzuch/jwt-pss` extension package
  that ships PS* on top of the public algorithm interface. Full
  rationale in [12 — Decisions](12-decisions.md).

## Phase 3 — JWE (target: v0.3)

**Goal.** Encryption support, including nested signed-then-encrypted JWTs.

### Deliverables

- **Key encryption.**
  - RSA-OAEP, RSA-OAEP-256.
  - RSA1_5 — **decrypt only**, encrypt path raises `UnsafeAlgorithmException`.
  - A128KW, A192KW, A256KW (AES Key Wrap).
  - A128GCMKW, A192GCMKW, A256GCMKW (AES-GCM Key Wrap).
  - ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW.
- **Content encryption.**
  - A128CBC-HS256, A192CBC-HS384, A256CBC-HS512.
  - A128GCM, A192GCM, A256GCM.
- ECDH-ES validation per NIST SP 800-56A r3 §5.6.2.3.4.
- JWE compact + flattened JSON serialization.
- **Nested JWT.** Sign-then-encrypt producers; consumers validate both
  layers; `cty` enforcement.
- Plaintext-replication consistency checks (RFC 7519 §5.3) — values present
  in both the JWE header and the encrypted Claims Set must match.

### Exit criteria

1. RFC 7516 §A and RFC 7520 cookbook encryption vectors pass.
2. Sanso invalid-curve PoC throws `DecryptionException`.
3. Nested JWT roundtrip with explicit typing on both inner and outer
   headers (RFC 8725 §3.11 closing paragraph).
4. RSA1_5 encrypt path throws and produces no output.

## Phase 4 — RFC 7797 & advanced JWS (target: v0.4)

**Goal.** Support large/detached payloads via `b64:false`, and JSON
serialization for multi-signature flows.

### Deliverables

- `b64:false` support at the JWS layer only. The JWT layer continues to
  refuse it with a clear exception message linking to RFC 7519's update.
- `crit:["b64"]` is mandatory whenever `b64:false` is used.
- Detached payload helpers (compact form with empty middle segment).
- JWS JSON Serialization, both general (multiple signatures) and flattened.
- Mixed-signature scenarios in tests.

### Exit criteria

1. RFC 7797 §4 example vectors pass.
2. JWT-layer test confirms `b64:false` is refused.
3. JWS JSON Serialization round-trip with two signatures of different
   algorithms.

## Phase 5 — Hardening, ergonomics, ecosystem (target: v1.0)

**Goal.** Take the library from "feature-complete" to "production-blessed",
and ship the Symfony bundle.

### Deliverables

- **Mutation testing.** MSI ≥ 90% across `src/`, ≥ 95% on `src/Algorithm/`
  and `src/Jws/`.
- **Fuzzing.** Parser-input fuzzing harness (nikic/php-fuzzer) integrated
  in CI as a nightly job. Findings tracked as GitHub Issues automatically.
- **PSR-3 logging hooks.** Optional logger. Never logs key material or full
  tokens — only `kid`, `alg`, profile, claim names involved in a failure.
- **Documentation.** Cookbook with worked examples for OAuth 2.0 access
  tokens, OIDC ID tokens, mTLS-bound tokens (RFC 8705), DPoP-bound tokens
  (RFC 9449 — basic posture, not full DPoP yet).
- **Performance pass.** Benchmark against `firebase/php-jwt` and
  `web-token/jwt-framework`. Document any defensible regressions.
- **Symfony bundle.** Shipped as `medzuch/jwt-bundle`, see
  [09-symfony-bundle-plan](09-symfony-bundle-plan.md).
- **API freeze and v1.0.0 tag.**

### Exit criteria

1. Mutation MSI targets met.
2. One full week of nightly fuzz runs with no novel crashes.
3. Public API surface frozen and documented as such in README.
4. CHANGELOG.md `1.0.0` section written.

## Phase 6 (optional, future) — PHP version upgrades

Tracked separately to keep the main roadmap honest. Bumping PHP versions
is a chore, not a feature.

### Triggers

- PHP 8.3 leaves security support (currently scheduled for **2027-12-31**).
- Or a compelling 8.4/8.5 feature lands (property hooks, asymmetric
  visibility, pipe operator).

### Plan

1. Add 8.4 to the CI matrix without making it required.
2. `composer require --dev rector/rector ^2.0` and commit a `rector.php`
   config targeting `LevelSetList::UP_TO_PHP_84`. Rector is intentionally
   not kept in `require-dev` during 8.3-only development — it earns its
   place only on upgrade.
3. Open a tracking issue listing every Rector rule that would apply.
4. Bump composer requirement to `~8.4.0 || ~8.3.0` for one minor version.
5. Run `vendor/bin/rector process`, review diffs by hand (especially
   anything touching crypto/parsing).
6. Drop 8.3 from the matrix in a major bump, never a minor.
7. Repeat for 8.5 only when 8.4 is universally available on the team's
   target hosting.

Once added, the Rector config makes future minor upgrades a `vendor/bin/rector
process && composer qa:full` away — not a rewrite.

## Phase numbering vs versioning

| Phase | Target version | Notes |
|-------|---------------|-------|
| 1 | v0.1.x | First usable for HS/RS JWTs |
| 2 | v0.2.x | All sig algorithms + profiles |
| 3 | v0.3.x | JWE shipped |
| 4 | v0.4.x | RFC 7797 + JSON serialization |
| 5 | v1.0.0 | Stable API + Symfony bundle |
| 6 | v2.x.x | PHP 8.4/8.5 baseline (whenever) |
