# 03 — RFC Compliance Matrix

A section-by-section accounting of how the library implements (or
intentionally diverges from) each normative requirement of the three core
RFCs. Status legend:

- ✅ implemented
- 🚧 planned in a later phase (see the phase number)
- 🚫 intentionally refused with rationale

## RFC 7519 — JSON Web Token

| Section | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| §3 | Represent JWT as JWS or JWE compact serialization | ✅ Phase 1 (JWS) / 🚧 Phase 3 (JWE) | |
| §4 | Reject duplicate Claim Names | ✅ Phase 1 | `Primitives\Json` |
| §4.1.1 | `iss` is StringOrURI, case-sensitive | ✅ Phase 1 | |
| §4.1.2 | `sub` is StringOrURI, case-sensitive | ✅ Phase 1 | |
| §4.1.3 | `aud` is array or single StringOrURI; normalised to list | ✅ Phase 1 | |
| §4.1.4 | `exp` is NumericDate; reject when now ≥ exp | ✅ Phase 1 | Leeway opt-in, bounded |
| §4.1.5 | `nbf` is NumericDate; reject when now < nbf | ✅ Phase 1 | Leeway opt-in, bounded |
| §4.1.6 | `iat` is NumericDate | ✅ Phase 1 | Sanity check: not implausibly far future |
| §4.1.7 | `jti` is case-sensitive string | ✅ Phase 1 | Uniqueness is application concern |
| §5.1 | `typ` declares media type | ✅ Phase 2 | Profiles enforce per-context |
| §5.2 | `cty` for nested JWT | 🚧 Phase 3 | |
| §5.3 | Claims replicated as JWE headers | 🚧 Phase 3 | Cross-checked on validate |
| §6 | Unsecured JWT (`alg:none`) | 🚫 | Opt-in only via separate API path |
| §7.1 | Creating a JWT, steps 1–6 | ✅ Phase 1 | |
| §7.2 | Validating a JWT, steps 1–10 | ✅ Phase 1 | |
| §7.3 | String comparison rules | ✅ Phase 1 | `Primitives\StringCompare` |
| §8 | HS256 and `none` mandatory; RS256/ES256 recommended | ✅ Phase 1 (HS/RS) / Phase 2 (ES) | `none` not enabled by default |
| §11.1 | Trust decisions require cryptographically secured tokens | ✅ Phase 1 | |
| §11.2 | Sign-then-encrypt order for Nested JWT | 🚧 Phase 3 | Producers enforce; consumers verify |
| §12 | Privacy considerations | ✅ Phase 1 | Documented |
| **Updated by 7797**: §3 implicitly forbids `b64:false` in JWTs | ✅ Phase 1 | JWT layer refuses `b64:false` |

## RFC 7797 — JWS Unencoded Payload Option

| Section | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| §3 | `b64` header parameter (boolean, default true) | 🚧 Phase 4 | JWS layer only |
| §3 | When `b64` is used, MUST be in protected header | 🚧 Phase 4 | |
| §3 | All signatures in a JWS MUST share the same `b64` value | 🚧 Phase 4 | |
| §5 | Restrictions on unencoded payload contents | 🚧 Phase 4 | Per-serialization validation |
| §5.1 | Detached payload may contain any octets | 🚧 Phase 4 | Helper for detached use |
| §5.2 | Compact serialization: payload MUST NOT contain `.` | 🚧 Phase 4 | Throws on encode if present |
| §5.3 | JSON serialization: must be UTF-8 of JSON-representable code points | 🚧 Phase 4 | |
| §6 | `crit` MUST include `b64` when `b64` is used | 🚧 Phase 4 | Enforced on encode/decode |
| §7 | Application profiles should specify `b64` usage | ✅ Phase 1 | Documented in API surface |
| §7 | **JWTs MUST NOT use `b64:false`** | ✅ Phase 1 | Refused at JWT layer |
| §8 | Security considerations | ✅ Phase 4 | Documented |

## RFC 8725 — JWT Best Current Practices

| Section | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| §3.1 | Algorithm verification (allowlist, one alg per key) | ✅ Phase 1 | Both rules baked in |
| §3.2 | Use appropriate algorithms; refuse `none` by default | ✅ Phase 1 | `none` opt-in only |
| §3.2 | Avoid RSA-PKCS1 v1.5 encryption | 🚫 deferred | All RSA-based JWE deferred; see [D-003](12-decisions.md#d-003--rsa-based-jwe-deferred-out-of-phase-3) |
| §3.2 | Deterministic ECDSA per RFC 6979 | 🚧 Phase 2 | Where backend supports it |
| §3.3 | Validate all cryptographic operations (including nested) | ✅ Phase 1 / 🚧 Phase 3 | |
| §3.4 | Validate cryptographic inputs (ECDH curve points) | 🚧 Phase 3 | NIST SP 800-56A r3 §5.6.2.3.4 |
| §3.5 | Sufficient key entropy; no human passwords as MAC keys | ✅ Phase 1 | `HmacKey` enforces minimum bytes |
| §3.6 | Avoid compression in encryption inputs | 🚧 Phase 3 | Off by default |
| §3.7 | UTF-8 only | ✅ Phase 1 | `Primitives\Json` and `Primitives\Utf8` |
| §3.8 | Validate issuer and subject | ✅ Phase 1 | |
| §3.9 | Validate audience | ✅ Phase 1 | |
| §3.10 | Do not trust received claims; sanitise `kid`, `jku`, `x5u` | ✅ Phase 1 / 🚧 Phase 2 | `jku`/`x5u` not auto-followed |
| §3.11 | Use explicit typing (`typ`) | ✅ Phase 2 | Profile-enforced |
| §3.12 | Mutually exclusive validation rules per JWT kind | ✅ Phase 2 | Profiles |

## RFC 7638 — JSON Web Key (JWK) Thumbprint

| Section | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| §3 | Thumbprint is the base64url hash of a JSON object of the key's required members | ✅ 1.3.0 | `Key\Thumbprint::of()` |
| §3.1 | Worked example | ✅ 1.3.0 | `Rfc7638Section31Test`; also RFC 8037 §A.3 (OKP) in `Rfc8037AppendixATest` and the RFC 9449 §6.1 `jkt` in `Rfc9449Section61Test` |
| §3.2 | Only the required members: RSA `e, kty, n`; EC `crv, kty, x, y`; `oct` `k, kty` | ✅ 1.3.0 / 🚫 `oct` | OKP `crv, kty, x` per RFC 8037 §2. Symmetric keys refused with `InvalidKeyException` — the thumbprint would digest the secret, and no confirmation method binds to one |
| §3.3 | Lexicographic member order, no whitespace, members in their JWK encodings | ✅ 1.3.0 | Built from `Key::toJwk()`, filtered; never the unfiltered JWK |
| §3.4 | Hash function chosen by the application | ✅ 1.3.0 | SHA-256 only — what `jkt` (RFC 9449 §6.1) specifies |
| §3.5 | Not a digest of X.509 values | ✅ 1.3.0 | Certificate thumbprints are a separate type, `Key\CertificateThumbprint` |

## RFC 8705 — OAuth 2.0 Mutual-TLS Certificate-Bound Access Tokens

| Section | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| §2 | Mutual-TLS client authentication | 🚫 | Transport; belongs to the TLS-terminating layer |
| §3 | AS binds the access token to the client certificate | ✅ 1.3.0 | `AccessTokenBuilder::confirmedBy(Confirmation::certificateThumbprint(...))` |
| §3.1 | `cnf.x5t#S256` is the base64url SHA-256 of the certificate's DER encoding | ✅ 1.3.0 | `Key\CertificateThumbprint::ofDer()` / `ofPem()`; values that are not an unpadded 32-byte digest refused |
| §3.1 | RS checks the presented certificate against `x5t#S256` | ✅ 1.3.0 (building blocks) | `ClaimsSet::confirmation()` + `CertificateThumbprint`; the comparison is the caller's, see [Cookbook §4](13-cookbook.md#4-mtls-bound-access-tokens-rfc-8705) |
| §3.2 | `cnf` in the token introspection response | 🚫 | Introspection needs an HTTP client; out of scope ([D-001](12-decisions.md#d-001--library-identity-is-standalone-zero-runtime-deps)) |
| §3.3, §3.4 | AS and client metadata (`tls_client_certificate_bound_access_tokens`) | 🚫 | Protocol metadata, not token handling |
| §5 | mTLS endpoint aliases | 🚫 | Protocol metadata, not token handling |
| RFC 7800 §3.1 | Confirmation members that are not understood MUST be ignored | ✅ 1.3.0 | `ClaimsSet::confirmation()` never throws on an unknown member |

## Algorithms supported per phase

| Algorithm | Type | Phase | Backend |
|-----------|------|-------|---------|
| `none` | Unsecured | 1 (opt-in) | — |
| HS256, HS384, HS512 | HMAC | 1 | `hash_hmac` |
| RS256, RS384, RS512 | RSA-PKCS1 v1.5 sig | 1 | OpenSSL |
| PS256, PS384, PS512 | RSA-PSS sig | deferred | see [Decision D-002](12-decisions.md#d-002--rsa-pss-ps256ps384ps512-deferred-out-of-phase-2) |
| ES256, ES384, ES512 | ECDSA | 2 | OpenSSL + RFC 6979 mode where possible |
| EdDSA (Ed25519) | EdDSA | 2 | libsodium |
| RSA-OAEP, RSA-OAEP-256 | Key encryption | deferred | see [Decision D-003](12-decisions.md#d-003--rsa-based-jwe-deferred-out-of-phase-3) |
| RSA1_5 | Key encryption | deferred | see [Decision D-003](12-decisions.md#d-003--rsa-based-jwe-deferred-out-of-phase-3) |
| `dir` | Direct (CEK = shared key) | 3 | — |
| A128KW, A192KW, A256KW | AES Key Wrap | 3 | OpenSSL (`aes-*-wrap`) |
| A128GCMKW, A192GCMKW, A256GCMKW | AES-GCM Key Wrap | 3 | OpenSSL |
| ECDH-ES, ECDH-ES+A*KW | Key agreement | 3 | libsodium (X25519), OpenSSL (P-256/384/521) |
| A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 | Content encryption | 3 | OpenSSL + `hash_hmac` |
| A128GCM, A192GCM, A256GCM | Content encryption | 3 | OpenSSL |

## Required JWT claims by profile

| Profile | `iss` | `sub` | `aud` | `exp` | `nbf` | `iat` | `jti` | `typ` |
|---------|:----:|:----:|:----:|:----:|:----:|:----:|:----:|------|
| Generic | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | optional |
| AccessToken (RFC 9068) | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | `at+jwt` |
| IdToken (OIDC) | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | optional |
| SET (RFC 8417) | ✓ | — | ✓ | — | — | ✓ | ✓ | `secevent+jwt` |
