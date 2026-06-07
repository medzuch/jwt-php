# 04 — Public API Surface

The minimum surface a caller interacts with. Everything else is `@internal`
and may change without notice.

## Mental model

```
            ┌──────────────────────────┐
            │  Profile (recommended)   │   ← 99% of callers stop here
            └────────────┬─────────────┘
                         │
       ┌─────────────────┴─────────────────┐
       │                                   │
┌──────▼──────┐                    ┌───────▼───────┐
│  JwtBuilder │                    │  JwtParser +  │
│             │                    │   Validator   │
└──────┬──────┘                    └───────┬───────┘
       │                                   │
       └────────────────┬──────────────────┘
                        │
                ┌───────▼────────┐
                │ JWS / JWE API  │   ← raw JOSE for advanced use
                └────────────────┘
```

If you find yourself reaching past the Profile layer, ask whether your
use case warrants a new profile.

For end-to-end, copy-pasteable flows (access tokens, ID tokens, remote JWKS,
mTLS/DPoP sender-constrained tokens, a Symfony authenticator), see
[13 — Cookbook](13-cookbook.md).

## Building tokens

```php
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Key\RsaPrivateKey;

$profile = AccessTokenProfile::issuer(
    issuer: 'https://issuer.example',
    algorithm: new Rs256(),
    signingKey: RsaPrivateKey::fromPem($pem, alg: 'RS256', kid: 'key-2026-01'),
);

$jwt = $profile->issue()
    ->subject('user-123')
    ->audience('https://api.example')
    ->clientId('web-app-1')
    ->scope(['read', 'write'])
    ->expiresIn(new \DateInterval('PT15M'))
    ->build();                       // CompactJws

echo (string) $jwt;
// eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0yMDI2LTAxIn0.eyJpc3M...
```

## Validating tokens

```php
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Algorithm\Signing\Es256;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Exception\ClaimValidationException;
use Medzuch\Jwt\Exception\JwtException;

$profile = AccessTokenProfile::consumer(
    expectedIssuer: 'https://issuer.example',
    expectedAudience: 'https://api.example',
    keys: JwkSet::fromArray($jwksDocument['keys']),
    allowedAlgorithms: [new Rs256(), new Es256()],   // concrete algorithm objects, never strings
);

try {
    $claims = $profile->parse($incomingJwt);
    // $claims is a ClaimsSet — fully validated.
    $userId = $claims->subject();
    $scopes = $claims->get('scope');
} catch (ClaimValidationException $e) {
    // Token was structurally valid but semantically wrong (expired, wrong aud, ...).
    $logger->info('JWT rejected', ['reason' => $e->getMessage()]);
    throw new UnauthorizedHttpException(...);
} catch (JwtException $e) {
    // Token was malformed or crypto failed.
    $logger->warning('JWT crypto/parse failure', ['reason' => $e->getMessage()]);
    throw new UnauthorizedHttpException(...);
}
```

## Logging (optional)

Every consume-side entry point accepts an optional PSR-3 logger and emits one
redacted event per outcome. It is entirely opt-in: with no logger, no
diagnostics code runs and `psr/log` is not required.

```php
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Psr\Log\LogLevel;

$profile = AccessTokenProfile::consumer(
    expectedIssuer: 'https://issuer.example',
    expectedAudience: 'https://api.example',
    keys: JwkSet::fromArray($jwksDocument['keys']),
    allowedAlgorithms: [new Rs256()],
    logger: $psrLogger,
    // Optional: remap the level of any event category. Defaults are secure
    // and quiet — accepted tokens at debug, integrity failures at warning.
    logLevels: new LogLevels(accepted: LogLevel::INFO),
);
```

The same `logger:` / `logLevels:` parameters exist on `ValidatorBuilder::withLogger()`,
the JWS `Verifier`, the JWE `Decrypter`, the other profile `consumer()` factories,
`RemoteJwksResolver`, and `NestedJwtParser` (which threads the logger to the inner
`Decrypter` and `Verifier` so the decrypt and inner-verify outcomes are logged).

**What is logged** — a fixed, non-sensitive allowlist only: `kid`, `alg`, `enc`,
`typ`, `profile`, the failing claim *name*, the `reason` (the exception's
short-class), and the configured `jwks_uri` / cache source.

**What is never logged** — tokens, payloads, claim *values*, key material, or
exception *messages* (which can embed values). Redaction is enforced in a single
internal sink, so the surface cannot be widened by accident.

## Lower-level API

For multi-tenant or custom flows.

### Builder

```php
use Medzuch\Jwt\Jwt\JwtBuilder;

$jwt = JwtBuilder::create()
    ->issuer('https://issuer.example')
    ->subject('user-123')
    ->audience('https://api.example')      // string or list
    ->expiresIn(new \DateInterval('PT15M'))
    ->notBeforeNow()
    ->issuedAtNow()
    ->jwtId(bin2hex(random_bytes(16)))
    ->type('at+jwt')                       // §3.11 explicit typing
    ->withClaim('scope', 'read write')
    ->withHeader('kid', 'key-2026-01')
    ->signWith($algorithm, $privateKey)
    ->build();
```

The builder is immutable. Each `with*` returns a new builder. `build()`
throws if mandatory pieces (algorithm + key, or `none` opt-in) are missing.

### Parser (two-phase)

```php
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Algorithm\Signing\Es256;

// Phase 1: structure only, no crypto yet.
$parsed = JwtParser::parse($compact);

// Inspect the header to pick a tenant key set:
$tenantId = $parsed->header()->get('tid');
$keys = $tenantKeyLookup->forTenant($tenantId);

// Phase 2: cryptographic + semantic validation.
$validator = ValidatorBuilder::create()
    ->expectAlgorithms([new Rs256(), new Es256()])
    ->withKeys($keys)
    ->expectIssuer('https://issuer.example')
    ->expectAudience('https://api.example')
    ->expectType('at+jwt')
    ->withLeeway(new \DateInterval('PT30S'))
    ->withClock($psr20Clock)
    ->requireClaims(['sub', 'exp', 'iat'])
    ->build();

$claims = $validator->validate($parsed);
```

## Reading the ClaimsSet

```php
$claims->issuer();        // ?string
$claims->subject();        // ?string
$claims->audience();       // list<string>, always a list
$claims->expiresAt();      // ?DateTimeImmutable
$claims->notBefore();      // ?DateTimeImmutable
$claims->issuedAt();       // ?DateTimeImmutable
$claims->jwtId();          // ?string

$claims->has('scope');     // bool
$claims->get('scope');     // mixed — JSON value as decoded
$claims->getString('scope');  // string|null, typed accessors throw on type mismatch
$claims->getList('roles');    // list<string>|null
$claims->getInt('seq');       // int|null
$claims->getBool('admin');    // bool|null
```

Typed accessors throw `ClaimTypeException` if the underlying value is the
wrong shape. Cleaner than checking with `is_string` everywhere.

## Key construction

```php
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\JwkSet;

// Symmetric
$hs256Key = HmacKey::fromBinary(random_bytes(32), alg: 'HS256');

// Asymmetric, from PEM
$rsaPriv = RsaPrivateKey::fromPem($pem, alg: 'RS256', kid: 'k1');
$rsaPub  = RsaPublicKey::fromPem($pem, alg: 'RS256', kid: 'k1');

// From JWK
$key = JwkParser::parse([
    'kty' => 'RSA',
    'alg' => 'RS256',
    'kid' => 'k1',
    'n'   => '...',
    'e'   => 'AQAB',
]);

// JWKS document
$set = JwkSet::fromArray($jwksDocument['keys']);
$key = $set->findByKid('k1');
```

## `none` algorithm (unsecured JWTs)

```php
use Medzuch\Jwt\Algorithm\Unsecured\None;
use Medzuch\Jwt\Jwt\UnsecuredJwtBuilder;

// Note: a dedicated builder, a dedicated namespace, a dedicated class name.
// You cannot accidentally end up here from the safe API.
$jwt = UnsecuredJwtBuilder::create()
    ->subject('user-123')
    ->expiresIn(new \DateInterval('PT15M'))
    ->build();
```

On the consumer side, `None::class` must be in the algorithm allowlist
explicitly, and the validator emits a warning via PSR-3 every time it is
used.

## What's not exposed

These exist as implementation details and may change:

- `Medzuch\Jwt\Primitives\*` — internal helpers.
- `Medzuch\Jwt\Jws\*\*Internal*` classes.
- Anything marked `@internal` in the docblock.

## Stability promise

**This surface is frozen as of v1.0.0.** From v1.0.0 onward the library follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) strictly:

- The public API described in this document will not change incompatibly within
  the 1.x line. Additions are made in minor releases; breaking changes wait for
  a 2.0.
- Bug-fix releases never break the public surface.
- "Public" means exactly what this document lists, plus everything reachable
  from it that is **not** marked `@internal`. Anything `@internal` — the
  `Medzuch\Jwt\Primitives\*` helpers, the `*\Internal\*` classes, and any member
  tagged `@internal` — may change in any release and is not covered by this
  promise.

What this freeze covers, concretely:

- the **Profile** layer (`AccessTokenProfile` / `IdTokenProfile` / `SetProfile`
  factories and the builder/consumer objects they return, including `parse()`,
  `issue()`, and the fluent setters);
- the **Builder / Parser / Validator** layer (`JwtBuilder`, `JwtParser`,
  `ValidatorBuilder`, `Validator`, `ClaimsSet`, `UnsecuredJwtBuilder`);
- **key construction** (`HmacKey`, `Rsa*Key`, `Ec*Key`, `Okp*Key`, `JwkParser`,
  `JwkSet`), the concrete **algorithm** classes, the **`Diagnostics`** logging
  hooks (`LogLevels`), the **`Key\Resolver`** contracts (`KeyResolver`,
  `RemoteJwksResolver`), and the **`Exception`** hierarchy callers catch.
