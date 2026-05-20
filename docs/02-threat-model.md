# 02 — Threat Model

This document enumerates the threats RFC 8725 highlights, plus a few from
the JOSE community's collective wreckage, and states how this library
mitigates each. Every mitigation links back to a code location (or a planned
one) so reviewers can verify it.

## Threat catalogue

### T1 — Algorithm "none" bypass

**Description.** An attacker crafts a JWT with `"alg":"none"` and an empty
signature. A library that trusts the header's `alg` field would "validate"
this and admit it. Multiple real-world libraries have done so.

**Reference.** [RFC 8725 §2.1][bcp-2.1], [CVE-2015-9235][cve].

**Mitigation.**
- `Validator` requires an explicit algorithm allowlist; `Algorithm::NONE` is
  not in any default allowlist.
- The `none` algorithm class is in a separate namespace
  (`Medzuch\Jwt\Algorithm\Unsecured\None`) so it cannot be added accidentally
  by a glob import.
- A unit test verifies that a JWT with `"alg":"none"` is rejected by every
  shipped profile.

### T2 — Algorithm confusion (RS256 → HS256)

**Description.** An attacker takes an RSA-signed token, changes `alg` to
`HS256`, and re-signs it using the public RSA key as the HMAC secret. A
naive library that picks the algorithm from the header validates it.

**Reference.** [RFC 8725 §2.1][bcp-2.1], [McLean 2015][mclean].

**Mitigation.**
- Allowlist enforcement.
- Key/algorithm binding: `RsaPublicKey` cannot be passed to an HMAC
  algorithm — the constructor of the algorithm rejects the key type.
- A dedicated regression test reproduces the McLean PoC and asserts the
  library throws `KeyMismatchException`.

### T3 — Weak symmetric key

**Description.** Caller uses a short or human-memorable string as the HMAC
secret. The token can be brute-forced offline once observed.

**Reference.** [RFC 8725 §2.2][bcp-2.2], [RFC 8725 §3.5][bcp-3.5].

**Mitigation.**
- `HmacKey::fromBinary` enforces the minimum byte length for each HS
  algorithm (32, 48, 64 bytes for HS256/384/512).
- No password-as-key constructor; documentation actively discourages it.

### T4 — Sign-then-encrypt inversion in JWE

**Description.** Encrypting first, signing the ciphertext later can let an
attacker strip the signature and replay the ciphertext.

**Reference.** [RFC 7519 §11.2][rfc7519-11.2].

**Mitigation.**
- Nested JWT producers in this library always **sign first, encrypt second**.
- Nested JWT consumers verify both layers (BCP §3.3) and refuse to admit a
  decrypted-but-unsigned inner JWT when the profile requires signing.

### T5 — Plaintext length leakage via compression

**Description.** Compressing before encrypting reveals plaintext properties
through ciphertext length, enabling adaptive chosen-plaintext attacks.

**Reference.** [RFC 8725 §2.4][bcp-2.4], [RFC 8725 §3.6][bcp-3.6].

**Mitigation.**
- JWE compression (`zip`) is **off by default**.
- The opt-in flag is named `enableUnsafeCompression()` and the docblock
  links to RFC 8725 §3.6.

### T6 — ECDH-ES invalid-curve attack

**Description.** ECDH key agreement with an attacker-chosen public key off
the named curve leaks bits of the recipient's private key.

**Reference.** [RFC 8725 §2.5][bcp-2.5], [Sanso][sanso], [Valenta et al.][valenta].

**Mitigation.**
- The ECDH-ES implementation validates the supplied `epk` against the
  recipient's chosen curve before performing the multiplication, per
  NIST SP 800-56A Rev. 3 §5.6.2.3.4.
- For X25519/X448, libsodium's `crypto_scalarmult` is used, which performs
  the necessary checks internally.
- A regression test feeds known invalid-curve points and asserts
  `DecryptionException`.

### T7 — Multi-encoding JSON ambiguity

**Description.** A recipient that accepts UTF-16/UTF-32-encoded JSON may
parse a token differently from the issuer, allowing claim smuggling.

**Reference.** [RFC 8725 §2.6][bcp-2.6], [RFC 8725 §3.7][bcp-3.7].

**Mitigation.**
- `Primitives\Json` accepts only UTF-8 byte strings; it explicitly rejects
  BOMs and validates byte-sequence well-formedness before handing the
  string to `json_decode`.
- The parser refuses tokens whose header or payload bytes are not valid
  UTF-8 after base64url-decoding.

### T8 — Substitution / audience confusion

**Description.** A token issued for service A is replayed against service B.

**Reference.** [RFC 8725 §2.7][bcp-2.7].

**Mitigation.**
- `Validator` requires the caller to declare expected `aud` values. A token
  with no `aud` is rejected by the access-token and ID-token profiles.
- Audience comparison is case-sensitive, per RFC 7519 §4.1.3.

### T9 — Cross-JWT confusion

**Description.** A token from one application (e.g. an OIDC ID Token) is
replayed where another kind of JWT (e.g. an access token) is expected.

**Reference.** [RFC 8725 §2.8][bcp-2.8].

**Mitigation.**
- Profiles enforce a specific `typ` value (BCP §3.11).
- Profiles enforce mutually exclusive required-claim sets (BCP §3.12).
- The access-token profile uses `application/at+jwt` per RFC 9068.

### T10 — `kid` injection

**Description.** A caller uses the `kid` value as a database key or
filesystem path without sanitisation, leading to SQL/LDAP injection or path
traversal.

**Reference.** [RFC 8725 §3.10][bcp-3.10].

**Mitigation.**
- The library never uses `kid` as anything but an opaque lookup key inside
  `JwkSet`. It documents the SSRF/injection risk for callers building
  custom resolvers.
- The default `RemoteJwksResolver` does not use `kid` to construct a URL;
  it fetches the `jwks_uri` once and looks `kid` up in-memory.

### T11 — `jku` / `x5u` SSRF

**Description.** A library that follows the `jku` or `x5u` URL from a
token's header allows an attacker to coerce the server into fetching from
arbitrary URLs, enabling SSRF.

**Reference.** [RFC 8725 §3.10][bcp-3.10].

**Mitigation.**
- Default resolvers do **not** consult `jku` or `x5u` at all.
- The opt-in resolver requires an explicit URL allowlist; URLs not on the
  allowlist throw `KeyNotFoundException` before any HTTP call.

### T12 — Timing leaks in signature comparison

**Description.** Byte-by-byte comparison of signatures leaks the position
of the first differing byte, enabling forgery for HMAC and other primitives
where comparison is in user code.

**Mitigation.**
- All signature comparisons go through `Primitives\ConstantTime::equals`,
  which wraps `hash_equals`.
- Static analysis (custom PHPStan rule, planned Phase 5) flags any `===` on
  strings inside `src/Algorithm/` or `src/Jws/`.

### T13 — Duplicate claim names

**Description.** RFC 7519 §4 mandates that duplicate claim names cause a
JWT to be rejected. A library using PHP's default `json_decode` silently
takes the last occurrence, hiding malicious values.

**Mitigation.**
- `Primitives\Json::decode` performs its own duplicate-key check before
  returning the decoded array.

### T14 — `b64:false` smuggling into JWTs

**Description.** RFC 7797 introduces `b64:false`. If accepted in a JWT,
non-base64 payloads can confuse downstream consumers.

**Reference.** [RFC 7797 §7][rfc7797-7] (which updates RFC 7519).

**Mitigation.**
- The JWT-layer parser refuses any header containing `b64:false`. The JWS
  layer accepts it for callers using raw JWS.

### T15 — Replay attacks

**Description.** A captured JWT is replayed before it expires.

**Mitigation.**
- The library exposes `jti`, `exp`, `nbf`, and `iat` validation. Replay
  prevention beyond `exp`/`nbf` (e.g. a `jti` blocklist) is the application's
  responsibility; the library documents this clearly and provides a
  `JtiBlocklist` interface for the integrator to implement.

## Non-mitigations

To be honest about what this library does *not* do:

- **Side-channel attacks on the underlying OpenSSL/libsodium primitives.**
  Those are upstream concerns. We use the highest-level safe wrappers
  available.
- **Compromise of the application's private keys.** Key storage is the
  application's responsibility. We can refuse to load weak keys, but we
  cannot keep a strong key safe in a leaky environment.
- **Quantum adversaries.** No post-quantum algorithms are in scope before
  the IETF settles on a JOSE PQ profile.

[bcp-2.1]: https://datatracker.ietf.org/doc/html/rfc8725#section-2.1
[bcp-2.2]: https://datatracker.ietf.org/doc/html/rfc8725#section-2.2
[bcp-2.4]: https://datatracker.ietf.org/doc/html/rfc8725#section-2.4
[bcp-2.5]: https://datatracker.ietf.org/doc/html/rfc8725#section-2.5
[bcp-2.6]: https://datatracker.ietf.org/doc/html/rfc8725#section-2.6
[bcp-2.7]: https://datatracker.ietf.org/doc/html/rfc8725#section-2.7
[bcp-2.8]: https://datatracker.ietf.org/doc/html/rfc8725#section-2.8
[bcp-3.5]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.5
[bcp-3.6]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.6
[bcp-3.7]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.7
[bcp-3.10]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.10
[rfc7519-11.2]: https://datatracker.ietf.org/doc/html/rfc7519#section-11.2
[rfc7797-7]: https://datatracker.ietf.org/doc/html/rfc7797#section-7
[cve]: https://nvd.nist.gov/vuln/detail/CVE-2015-9235
[mclean]: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
[sanso]: https://blogs.adobe.com/security/2017/03/critical-vulnerability-uncovered-in-json-encryption.html
[valenta]: https://ia.cr/2018/298
