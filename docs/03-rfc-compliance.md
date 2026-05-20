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
| §3.2 | Avoid RSA-PKCS1 v1.5 encryption | 🚧 Phase 3 | RSA1_5 decrypt-only for legacy |
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

## Algorithms supported per phase

| Algorithm | Type | Phase | Backend |
|-----------|------|-------|---------|
| `none` | Unsecured | 1 (opt-in) | — |
| HS256, HS384, HS512 | HMAC | 1 | `hash_hmac` |
| RS256, RS384, RS512 | RSA-PKCS1 v1.5 sig | 1 | OpenSSL |
| PS256, PS384, PS512 | RSA-PSS sig | 2 | OpenSSL |
| ES256, ES384, ES512 | ECDSA | 2 | OpenSSL + RFC 6979 mode where possible |
| EdDSA (Ed25519) | EdDSA | 2 | libsodium |
| RSA-OAEP, RSA-OAEP-256 | Key encryption | 3 | OpenSSL |
| RSA1_5 | Key encryption | 3 (decrypt-only) | OpenSSL |
| A128KW, A192KW, A256KW | AES Key Wrap | 3 | OpenSSL |
| A128GCMKW, A192GCMKW, A256GCMKW | AES-GCM Key Wrap | 3 | OpenSSL |
| ECDH-ES, ECDH-ES+A*KW | Key agreement | 3 | libsodium (X25519/X448), OpenSSL (P-*) |
| A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 | Content encryption | 3 | OpenSSL + `hash_hmac` |
| A128GCM, A192GCM, A256GCM | Content encryption | 3 | OpenSSL |

## Required JWT claims by profile

| Profile | `iss` | `sub` | `aud` | `exp` | `nbf` | `iat` | `jti` | `typ` |
|---------|:----:|:----:|:----:|:----:|:----:|:----:|:----:|------|
| Generic | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | optional |
| AccessToken (RFC 9068) | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | `at+jwt` |
| IdToken (OIDC) | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | optional |
| SET (RFC 8417) | ✓ | — | ✓ | — | — | ✓ | ✓ | `secevent+jwt` |
