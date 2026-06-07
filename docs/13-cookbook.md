# 13 — Cookbook

Worked, copy-pasteable recipes for the flows people actually build. Each one
uses the **Profile** layer ([04 — Public API Surface](04-api-surface.md)) —
the highest, hardest-to-misuse surface — and reaches lower only where a recipe
genuinely needs it.

Conventions used below:

- `$pem` / `$jwksDocument` are loaded however your app loads secrets and
  config; they are never hard-coded.
- Algorithms are always concrete objects (`new Rs256()`), never strings — the
  library has no string→algorithm lookup by design (RFC 8725 §2.1, algorithm
  confusion).
- Every `consumer(...)` / `parse(...)` either returns a fully validated
  `ClaimsSet` or throws a `JwtException` subclass. There is no "valid-ish"
  middle state.

| # | Recipe |
|---|--------|
| 1 | [OAuth 2.0 access tokens (RFC 9068)](#1-oauth-20-access-tokens-rfc-9068) |
| 2 | [OIDC ID tokens](#2-oidc-id-tokens) |
| 3 | [Rotating keys via a remote JWKS](#3-rotating-keys-via-a-remote-jwks) |
| 4 | [mTLS-bound access tokens (RFC 8705)](#4-mtls-bound-access-tokens-rfc-8705) |
| 5 | [DPoP-bound access tokens (RFC 9449, basic posture)](#5-dpop-bound-access-tokens-rfc-9449-basic-posture) |
| 6 | [The core library inside a Symfony authenticator](#6-the-core-library-inside-a-symfony-authenticator) |

---

## 1. OAuth 2.0 access tokens (RFC 9068)

`AccessTokenProfile` bakes in the RFC 9068 invariants: the `at+jwt` header
type, the `iss`/`exp`/`aud`/`sub`/`iat`/`jti`/`client_id` claim set, and a
random `jti` per token. You supply the policy; it supplies the correctness.

### Issuing (authorization server)

```php
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Key\RsaPrivateKey;

$profile = AccessTokenProfile::issuer(
    issuer: 'https://issuer.example',
    algorithm: new Rs256(),
    signingKey: RsaPrivateKey::fromPem($pem, alg: 'RS256', kid: 'key-2026-01'),
);

$accessToken = $profile->issue()
    ->subject('user-123')                       // the resource owner
    ->audience('https://api.example')           // the protected resource
    ->clientId('web-app-1')                     // RFC 9068 §2.2
    ->scope(['documents:read', 'documents:write'])
    ->expiresIn(new \DateInterval('PT15M'))
    ->build();                                  // CompactJws

return (string) $accessToken;
```

`iss`, `iat`, `jti`, the `typ` header, and the `kid` (from the signing key)
are filled in for you. Anything you set is last-write-wins, so you can override
`jti`/`iat` if you mint identifiers elsewhere.

### Consuming (resource server)

```php
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Algorithm\Signing\Es256;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Exception\ClaimValidationException;
use Medzuch\Jwt\Exception\JwtException;

$consumer = AccessTokenProfile::consumer(
    expectedIssuer: 'https://issuer.example',
    expectedAudience: 'https://api.example',
    keys: JwkSet::fromArray($jwksDocument['keys']),
    allowedAlgorithms: [new Rs256(), new Es256()],   // your accepted set, nothing else
);

try {
    $claims = $consumer->parse($bearerToken);        // ClaimsSet — fully validated
    $userId = $claims->subject();
    $scopes = explode(' ', $claims->getString('scope') ?? '');   // see note below
} catch (ClaimValidationException $e) {
    // Structurally valid, semantically wrong: expired, wrong aud, missing claim.
    throw new AccessDeniedHttpException('invalid_token');
} catch (JwtException $e) {
    // Malformed, wrong type, or signature/crypto failure.
    throw new AccessDeniedHttpException('invalid_token');
}
```

The consumer enforces `typ: at+jwt`, the issuer, the audience, the required
claim set, and `exp`/`nbf` (with optional leeway). You only decide what to do
with a validated subject.

> **Scope shape.** RFC 9068 carries `scope` as a single space-delimited string
> (`"documents:read documents:write"`), per RFC 6749 §3.3. `->scope([...])`
> joins for you on the issue side; on the consume side use
> `$claims->getString('scope')` and `explode(' ', …)`, or `getList('scope')`
> if your issuer (non-standardly) emits an array.

---

## 2. OIDC ID tokens

`IdTokenProfile` mirrors the access-token profile but for OpenID Connect: the
audience **is** the client, and `nonce` replay protection is first-class.

### Issuing (OpenID Provider)

```php
use Medzuch\Jwt\Profile\IdTokenProfile;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Key\RsaPrivateKey;

$profile = IdTokenProfile::issuer(
    issuer: 'https://issuer.example',
    algorithm: new Rs256(),
    signingKey: RsaPrivateKey::fromPem($pem, alg: 'RS256', kid: 'key-2026-01'),
);

$idToken = $profile->issue()
    ->subject('user-123')                       // stable, per-issuer user id
    ->audience('web-app-1')                      // the OAuth client_id
    ->nonce($nonceFromAuthorizationRequest)      // bind to the auth request
    ->authTime(new \DateTimeImmutable('-2 minutes'))
    ->acr('urn:mace:incommon:iap:silver')
    ->amr(['pwd', 'otp'])
    ->expiresIn(new \DateInterval('PT1H'))
    ->withClaim('email', 'user@example.com')     // any extra claims you assert
    ->build();
```

### Consuming (Relying Party)

```php
use Medzuch\Jwt\Profile\IdTokenProfile;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Key\JwkSet;

$consumer = IdTokenProfile::consumer(
    expectedIssuer: 'https://issuer.example',
    clientId: 'web-app-1',                       // becomes the expected audience
    keys: JwkSet::fromArray($jwksDocument['keys']),
    allowedAlgorithms: [new Rs256()],
    expectedNonce: $nonceFromSession,            // if set, token nonce MUST match
);

$claims = $consumer->parse($idToken);            // throws on any mismatch
$subject = $claims->subject();
$authedAt = $claims->get('auth_time');
```

Passing `expectedNonce:` makes a missing or mismatched `nonce` a hard failure
(OIDC Core §3.1.3.7). Omit it only for flows where no nonce was sent.

---

## 3. Rotating keys via a remote JWKS

In production you rarely hand the consumer a static `JwkSet`; you point it at
the issuer's `jwks_uri` and let it follow key rotation. `RemoteJwksResolver` is
a `KeyResolver`, so it drops straight into any `consumer(keys: …)` slot in
place of a `JwkSet`.

```php
use Medzuch\Jwt\Key\Resolver\RemoteJwksResolver;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\Jwt\Algorithm\Signing\Rs256;

// Four of the five collaborators are standard PSR interfaces — bring your own.
$resolver = new RemoteJwksResolver(
    jwksUri: 'https://issuer.example/.well-known/jwks.json',  // must be https://
    httpClient: $psr18Client,
    requestFactory: $psr17RequestFactory,
    cache: $psr16Cache,
    clock: $psr20Clock,
    cacheTtlSeconds: 3600,        // how long a fetched JWKS is trusted
    minRefreshSeconds: 300,       // floor between rotation-triggered refetches
);

$consumer = AccessTokenProfile::consumer(
    expectedIssuer: 'https://issuer.example',
    expectedAudience: 'https://api.example',
    keys: $resolver,              // ← resolver instead of a static JwkSet
    allowedAlgorithms: [new Rs256()],
);

$claims = $consumer->parse($bearerToken);
```

The resolver caches the document, matches the token's `kid`, and refetches at
most once per `minRefreshSeconds` when an unknown `kid` appears (so a rotation
is picked up without letting an attacker spam your JWKS endpoint). The response
body is size-capped (`maxBodyBytes`) and the URL must be `https://`.

---

## 4. mTLS-bound access tokens (RFC 8705)

A sender-constrained token carries a confirmation (`cnf`) claim that ties it to
a client credential, so a stolen token is useless without that credential. For
mTLS the confirmation is `x5t#S256` — the base64url SHA-256 of the client
certificate (DER). The library has no dedicated mTLS API; you assert and read
the `cnf` claim with the generic building blocks.

### Issuing — bind the token to the client certificate

`$profile` is the `AccessTokenProfile::issuer(...)` from recipe 1.

```php
// $clientCertDer: the client's certificate in DER form, from the TLS handshake
// that authenticated the token request.
$thumbprint = rtrim(strtr(base64_encode(hash('sha256', $clientCertDer, true)), '+/', '-_'), '=');

$accessToken = $profile->issue()
    ->subject('user-123')
    ->audience('https://api.example')
    ->clientId('service-a')
    ->scope(['documents:read'])
    ->expiresIn(new \DateInterval('PT15M'))
    ->withClaim('cnf', ['x5t#S256' => $thumbprint])   // RFC 8705 §3.1
    ->build();
```

### Consuming — enforce the binding

Validating the token's signature and claims is necessary but **not
sufficient**: you must also prove the *current* connection presents the same
certificate the token was bound to.

```php
$claims = $consumer->parse($bearerToken);   // signature + claims first

$cnf = $claims->get('cnf');
$bound = is_array($cnf) ? ($cnf['x5t#S256'] ?? null) : null;
if ($bound === null) {
    throw new AccessDeniedHttpException('invalid_token');   // not a bound token
}

// The cert from THIS request's TLS layer (e.g. SSL_CLIENT_CERT → DER).
$presented = rtrim(strtr(base64_encode(hash('sha256', $presentedCertDer, true)), '+/', '-_'), '=');

if (!hash_equals($bound, $presented)) {
    throw new AccessDeniedHttpException('invalid_token');    // token replayed on a different connection
}
```

> Compare thumbprints with `hash_equals()`, never `===` — the same
> constant-time discipline the library enforces internally (threat-model T12).
> Extracting and DER-encoding the peer certificate is the responsibility of
> your TLS-terminating layer; this library deliberately stays out of the
> transport.

---

## 5. DPoP-bound access tokens (RFC 9449, basic posture)

DPoP binds a token to a key the client holds, proving possession with a signed
`DPoP` proof JWT on each request. The token's confirmation is `cnf.jkt` — the
JWK SHA-256 thumbprint (RFC 7638) of the client's public key.

### Issuing — bind to the client's DPoP key

`$profile` is the `AccessTokenProfile::issuer(...)` from recipe 1.

```php
// $jkt: the RFC 7638 thumbprint of the client's DPoP public key, taken from
// the DPoP proof presented at the token endpoint.
$accessToken = $profile->issue()
    ->subject('user-123')
    ->audience('https://api.example')
    ->clientId('spa-1')
    ->expiresIn(new \DateInterval('PT5M'))
    ->withClaim('cnf', ['jkt' => $jkt])               // RFC 9449 §6
    ->build();
```

### Consuming — match the proof's key to the binding

On each request the resource server validates the `DPoP` proof JWT (its `htm`,
`htu`, `iat`, `jti` replay window, and signature against the embedded JWK),
then compares that key's thumbprint to the token's `cnf.jkt`.

```php
$claims = $consumer->parse($bearerToken);

$cnf = $claims->get('cnf');
$boundJkt = is_array($cnf) ? ($cnf['jkt'] ?? null) : null;
if ($boundJkt === null) {
    throw new AccessDeniedHttpException('invalid_token');
}

// $proofJkt: thumbprint of the public key the validated DPoP proof was
// signed with (you compute this while verifying the proof).
if (!hash_equals($boundJkt, $proofJkt)) {
    throw new AccessDeniedHttpException('invalid_token');
}
```

> **Scope of this recipe.** This library issues and reads the `cnf.jkt`
> binding. Generating and verifying the `DPoP` proof JWT itself — including
> `htm`/`htu` matching and `jti` replay caching — is application protocol work
> outside the token library. The JWS verification *inside* proof validation
> can of course use this library's `Verifier`.

---

## 6. The core library inside a Symfony authenticator

A dedicated `medzuch/jwt-bundle` is planned (see
[09 — Symfony Bundle Plan](09-symfony-bundle-plan.md)), but you do not need it.
The core library drops into a custom authenticator in ~50 lines. Build the
`AccessTokenConsumer` once as a service and inject it.

```php
// config/services.php — wire the consumer as a service.
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\Jwt\Profile\AccessTokenConsumer;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Key\Resolver\RemoteJwksResolver;

$services->set(AccessTokenConsumer::class)
    ->factory([AccessTokenProfile::class, 'consumer'])
    ->args([
        '$expectedIssuer'    => 'https://issuer.example',
        '$expectedAudience'  => 'https://api.example',
        '$keys'              => service(RemoteJwksResolver::class),
        '$allowedAlgorithms' => [inline_service(Rs256::class)],
        '$logger'            => service('logger'),   // optional PSR-3
    ]);
```

```php
namespace App\Security;

use Medzuch\Jwt\Profile\AccessTokenConsumer;
use Medzuch\Jwt\Exception\JwtException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class JwtAuthenticator extends AbstractAuthenticator
{
    public function __construct(private readonly AccessTokenConsumer $consumer) {}

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization')
            && str_starts_with($request->headers->get('Authorization', ''), 'Bearer ');
    }

    public function authenticate(Request $request): Passport
    {
        $token = substr($request->headers->get('Authorization', ''), 7);

        try {
            $claims = $this->consumer->parse($token);   // signature + RFC 9068 claims
        } catch (JwtException $e) {
            // One opaque message: never leak why a token was rejected.
            throw new CustomUserMessageAuthenticationException('Invalid credentials.');
        }

        $userId = $claims->subject()
            ?? throw new CustomUserMessageAuthenticationException('Invalid credentials.');

        // SelfValidatingPassport: the JWT *is* the proof — no password re-check.
        // Attach scopes/roles via the UserBadge loader or a custom badge.
        return new SelfValidatingPassport(new UserBadge($userId));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new Response('', 401, ['WWW-Authenticate' => 'Bearer']);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;   // let the request continue
    }
}
```

That is the whole integration: parse in `authenticate()`, map `sub` to a user,
collapse every failure to one opaque message. The planned bundle will add
per-profile authenticator services, a claims-based user provider, and DI
configuration — but the security boundary is exactly the `parse()` call above.

---

## Where to go next

- [04 — Public API Surface](04-api-surface.md) — the full surface, including
  the lower-level `JwtBuilder` / `JwtParser` + `ValidatorBuilder` for
  multi-tenant key selection.
- [02 — Threat Model](02-threat-model.md) — why the consumer is strict by
  default and what each check defends against.
- [10 — Security Policy](10-security-policy.md) — reporting and supported
  versions.
