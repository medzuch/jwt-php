# 01 — Architecture

## Design principles

These are the rules every layer follows. They are derived from RFC 8725 and
the security lessons of the past decade. They are not negotiable; if a
proposed change conflicts with one, the change loses.

1. **Algorithm allowlist, never `alg`-driven dispatch.** The caller declares
   which algorithm(s) they expect; the library refuses anything else.
   ([RFC 8725 §3.1][bcp-3.1])
2. **One key, one algorithm.** Keys carry their algorithm binding. A key
   object cannot be used with the wrong primitive.
   ([RFC 8725 §3.1][bcp-3.1])
3. **`none` is opt-in, explicit, and on a separate type.** The default builder
   and parser refuse it. ([RFC 8725 §3.2][bcp-3.2])
4. **Strict typing via `typ`** using the `application/<name>+jwt` convention.
   ([RFC 8725 §3.11][bcp-3.11])
5. **Mutually exclusive validation profiles** rather than a single permissive
   validator. ([RFC 8725 §3.12][bcp-3.12])
6. **UTF-8 only.** Reject anything else; reject duplicate claim names;
   constant-time signature comparison.
   ([RFC 7519 §4][rfc7519-4], [RFC 8725 §3.7][bcp-3.7])
7. **`b64:false` is forbidden in JWTs.** RFC 7519 is updated by RFC 7797 to
   that effect. The JWS layer supports it; the JWT layer refuses it.
   ([RFC 7797 §7][rfc7797-7])
8. **Leeway is explicit and bounded.** No silent defaults beyond a low
   ceiling. ([RFC 7519 §4.1.4][rfc7519-4.1.4])
9. **Fail-closed everywhere.** Any validation failure throws a typed
   exception; no truthy/falsy soup, no silent "best effort".

## Layered architecture

The library has **six layers**. Each layer has one job and depends only on
layers below it. Higher layers compose lower ones; lower layers know nothing
about higher ones.

```
┌────────────────────────────────────────────────────────────┐
│  6. Profiles          (AccessTokenProfile, IdTokenProfile, │
│                        SetProfile, custom builder)         │
├────────────────────────────────────────────────────────────┤
│  5. JWT API           (Builder, Parser, Validator,         │
│                        ClaimsSet, Header)                  │
├────────────────────────────────────────────────────────────┤
│  4. JWS / JWE         (Signer, Verifier, Encrypter,        │
│                        Decrypter, Serializer)              │
├────────────────────────────────────────────────────────────┤
│  3. Algorithms        (HS256/384/512, RS256/384/512,       │
│                        PS256/.., ES256/384/512, EdDSA,     │
│                        RSA-OAEP, ECDH-ES, A128/256GCM..)   │
├────────────────────────────────────────────────────────────┤
│  2. Keys              (JWK, JwkSet, key resolvers,         │
│                        algorithm binding, JWKS fetcher)    │
├────────────────────────────────────────────────────────────┤
│  1. Primitives        (Base64Url, Json, ConstantTime,      │
│                        Clock, Random, Utf8 validation)     │
└────────────────────────────────────────────────────────────┘
```

### Layer 1 — Primitives

Small, audited, dependency-free helpers. Lives in `src/Primitives/`.

| Class | Responsibility |
|-------|----------------|
| `Base64Url` | Encode/decode per RFC 7515 §2; wraps PHP's constant-time `sodium_bin2base64` / `sodium_base642bin` with `SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING`. |
| `Json` | UTF-8-only encode/decode with bounded depth and duplicate-key rejection. |
| `ConstantTime` | `equals(string, string): bool` wrapping `hash_equals`. |
| `Clock` | PSR-20 wrapper with a frozen-clock implementation for tests. |
| `Random` | `bytes(int): string` wrapping `random_bytes`. |
| `Utf8` | Validates a byte string is well-formed UTF-8 without overlongs or surrogates. |

These are the only places in the library that touch raw byte-level encoding
concerns. Every other layer asks one of these and trusts the answer.

### Layer 2 — Keys

Models RFC 7517 JWK fully, plus algorithm binding from RFC 8725 §3.1.

```
Key (abstract)
├── SymmetricKey
│   └── HmacKey         (enforces min entropy per algorithm)
├── AsymmetricKey (abstract)
│   ├── RsaKey { Public | Private }
│   ├── EcKey  { Public | Private }   (P-256, P-384, P-521)
│   └── OkpKey { Public | Private }   (Ed25519, X25519)
└── JwkSet                            (collection, lookup by kid)
```

A `Key` carries:

- `kid` (optional but recommended).
- `alg` — the **one** algorithm this key is bound to. Once set, the key
  refuses to be used with any other.
- `use` (`sig` or `enc`) and/or `key_ops`.

Key creation goes through one of:

- `JwkParser::parse(array $jwk): Key`
- `PemKeyLoader::loadPrivateKey(string $pem, string $alg): PrivateKey`
- `HmacKey::fromBinary(string $bytes, string $alg): HmacKey`

`HmacKey::fromBinary` rejects keys shorter than the algorithm's hash output
size (256 bits for HS256, 384 for HS384, 512 for HS512), implementing
RFC 8725 §3.5. There is **no** password-derived-key constructor; that is
intentional.

#### Key resolvers

```php
interface KeyResolver
{
    /** @throws KeyNotFoundException */
    public function resolve(Header $header): Key;
}
```

Three ship in the box:

- `StaticJwkSetResolver` — fixed set from config.
- `RemoteJwksResolver` — fetches an **https-only** `jwks_uri` through an
  injected PSR-18 client (TLS verification is the client's responsibility),
  caches the document via PSR-16, and on a `kid` miss refetches once —
  throttled by a PSR-20 clock so unknown-`kid` tokens cannot amplify into a
  fetch storm. Response bodies are size-capped before parsing. The PSR
  HTTP/cache packages are opt-in (`suggest`), so the library's only hard
  runtime dependency stays `psr/clock`.
- `CompositeResolver` — tries resolvers in order, falling through on any
  failure (a miss or a flaky remote). The key building block for rotation
  windows: a trusted local set first, a remote resolver behind it.

**`jku` and `x5u` headers are never followed by default.** Even when
enabled, they require an explicit URL allowlist on the resolver
([RFC 8725 §3.10][bcp-3.10]).

### Layer 3 — Algorithms

Stateless strategy objects, one class per `alg`. Lives in `src/Algorithm/`.

```php
interface Algorithm
{
    public function name(): string;             // "RS256", "ES256", ...
    public function family(): AlgorithmFamily;  // HMAC | RSA | ECDSA | EdDSA | NONE
}

interface SigningAlgorithm extends Algorithm
{
    public function sign(string $input, PrivateKey $key): string;
    public function verify(string $input, string $signature, PublicKey $key): bool;
}

interface KeyEncryptionAlgorithm extends Algorithm { /* ... */ }
interface ContentEncryptionAlgorithm extends Algorithm { /* ... */ }
```

Algorithms are wired by the caller, e.g.:

```php
$validator = ValidatorBuilder::create()
    ->expectAlgorithms([Rs256::class, Es256::class])
    ->withKeys($jwkSet)
    ->build();
```

The library refuses any `alg` value not in the allowlist, regardless of what
the JWS header claims.

#### Crypto backend selection

For each operation we prefer **libsodium** where it offers a constant-time
implementation, falling back to **OpenSSL** otherwise.

| Algorithm | Backend |
|-----------|---------|
| HS256/384/512 | `hash_hmac` (constant-time `hash_equals` for compare) |
| RS256/384/512 | OpenSSL |
| PS256/384/512 (RSA-PSS) | OpenSSL |
| ES256/384/512 | OpenSSL, with RFC 6979 deterministic-`k` mode where the underlying lib offers it |
| EdDSA (Ed25519) | libsodium (`sodium_crypto_sign_*`) |
| ECDH-ES (X25519) | libsodium |
| ECDH-ES (P-256/384/521) | OpenSSL with explicit point-on-curve validation |
| A128/192/256GCM | OpenSSL (AES-GCM) |
| A128/256CBC-HS256/512 | OpenSSL (CBC) + `hash_hmac` |

### Layer 4 — JWS / JWE

The full JOSE serialization layer. Usable on its own for raw JWS/JWE
workflows (e.g. signing a large document with `b64:false` detached payload).

| Module | Responsibility |
|--------|----------------|
| `Jws\Signer` | Compute a JWS from a payload, header, and signing key. |
| `Jws\Verifier` | Verify a JWS given an algorithm allowlist and key resolver. |
| `Jws\CompactSerializer` | Produce/parse the dot-separated compact form. |
| `Jws\JsonSerializer` | Produce/parse the JSON serialization (flattened + general). |
| `Jwe\Encrypter` | Build a JWE. |
| `Jwe\Decrypter` | Decrypt and authenticate a JWE. |

This is the only layer that knows about `b64:false`. The JWT layer above it
refuses to allow that header value through.

### Layer 5 — JWT API

The compact-serialization-only surface mandated by RFC 7519. Lives in
`src/Jwt/`.

```php
// Build
$jwt = JwtBuilder::create()
    ->issuer('https://issuer.example')
    ->subject('user-123')
    ->audience('https://api.example')
    ->expiresIn(new \DateInterval('PT15M'))
    ->issuedAtNow()
    ->jwtId(Uuid::v7())
    ->type('at+jwt')
    ->withClaim('scope', 'read write')
    ->signWith($algorithm, $privateKey)
    ->build();                       // CompactJws

// Parse (two-phase)
$parsed = JwtParser::parse($compact);                // structure only
$claims = $validator->validate($parsed);             // crypto + semantics
```

#### Why two-phase parsing

A multi-tenant system needs to inspect the `kid` header before choosing a
key set. With a single-phase API, the caller would have to peek into the
header by base64-decoding manually — defeating the safety the library
provides. Two-phase makes the inspection step a first-class API while still
forcing crypto validation through the validator.

### Layer 6 — Profiles

Pre-configured validators for common application contexts.

| Profile | Spec | Required claims | Required `typ` |
|---------|------|-----------------|----------------|
| `AccessTokenProfile` | RFC 9068 | `iss`, `aud`, `exp`, `sub`, `client_id`, `iat`, `jti` | `at+jwt` |
| `IdTokenProfile` | OIDC Core 1.0 | `iss`, `sub`, `aud`, `exp`, `iat` | unset |
| `SetProfile` | RFC 8417 (SETs) | `iss`, `iat`, `jti`, `events` | `secevent+jwt` |

Each profile has two sides: a reusable `::issuer(...)` whose `issue()`
returns a fluent builder that pre-stamps the producer-side invariants
(`typ`, `iss`, `iat`, and — where the spec requires it — a random `jti`),
and a `::consumer(...)` whose `parse()` runs the full validator plus the
token-kind-specific semantic checks (`azp`/`nonce` for ID tokens, the
`events` object shape for SETs). Algorithm allowlists are concrete
`SigningAlgorithm` objects, never strings — the same no-string-registry
rule as the rest of the library.

`IdTokenProfile` does not enforce a `typ`: OIDC Core does not mandate one
and most identity providers omit `id+jwt`. `SetProfile` requires
`secevent+jwt`, which RFC 8417 only RECOMMENDS — stricter than the spec,
in line with the library's explicit-typing posture (RFC 8725 §3.11).

A Symfony Guard later picks one of these and gets a fully validated
`ClaimsSet` back, or a typed exception.

## Object model (excerpt)

See [04 — Public API Surface](04-api-surface.md) for the full surface. The
core DTOs are immutable readonly classes:

```php
final readonly class ClaimsSet
{
    public function __construct(
        private array $claims, // validated, UTF-8, no duplicate keys
    ) {}
    public function issuer(): ?string {}
    public function subject(): ?string {}
    public function audience(): array {}             // always a list, never a string
    public function expiresAt(): ?\DateTimeImmutable {}
    public function notBefore(): ?\DateTimeImmutable {}
    public function issuedAt(): ?\DateTimeImmutable {}
    public function jwtId(): ?string {}
    public function get(string $name): mixed {}
    public function has(string $name): bool {}
}

final readonly class Header { /* same shape for protected header */ }

final readonly class CompactJws
{
    public function __construct(public string $value) {}
    public function __toString(): string { return $this->value; }
}
```

## Exception hierarchy

A typed hierarchy. Every failure is one of these. Catching the marker
interface `JwtException` catches anything from the library.

```
JwtException (interface)
├── MalformedJwtException
├── InvalidHeaderException
├── AlgorithmNotAllowedException
├── KeyNotFoundException
├── KeyMismatchException
├── SignatureVerificationException
├── ClaimValidationException
│   ├── ExpiredException                (exp)
│   ├── NotYetValidException            (nbf)
│   ├── IssuedInFutureException         (iat sanity)
│   ├── InvalidIssuerException
│   ├── InvalidAudienceException
│   ├── InvalidSubjectException
│   ├── InvalidTypeException            (typ mismatch)
│   └── MissingClaimException
└── DecryptionException
```

No swallowing, no booleans-on-error. Every leaf class is `final`.

## What is out of scope (and why)

- **Automatic `jku`/`x5u` fetching by default** — RFC 8725 §3.10 calls this out
  explicitly as an SSRF vector. The opt-in path requires an explicit URL
  allowlist on the resolver.
- **Compression in JWE by default** — RFC 8725 §3.6. The opt-in path exists
  for legacy interop but is gated behind a flag with the BCP referenced in
  the docblock.
- **Plaintext claim shortcuts in JWE** — supported per RFC 7519 §5.3, but the
  validator cross-checks them against the encrypted set and rejects on
  mismatch.
- **Password-derived HMAC keys** — RFC 8725 §3.5. There is no constructor for
  this. Callers who must do it can build a key from `hash_pbkdf2` output and
  pass the bytes to `HmacKey::fromBinary`, but the library will not lead
  them down that path.

[bcp-3.1]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.1
[bcp-3.2]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.2
[bcp-3.5]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.5
[bcp-3.6]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.6
[bcp-3.7]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.7
[bcp-3.10]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.10
[bcp-3.11]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.11
[bcp-3.12]: https://datatracker.ietf.org/doc/html/rfc8725#section-3.12
[rfc7519-4]: https://datatracker.ietf.org/doc/html/rfc7519#section-4
[rfc7519-4.1.4]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
[rfc7797-7]: https://datatracker.ietf.org/doc/html/rfc7797#section-7
