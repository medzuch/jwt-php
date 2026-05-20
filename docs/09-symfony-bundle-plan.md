# 09 — Symfony Bundle Plan

This document outlines how the core library will be wrapped in a Symfony
bundle. The bundle is intentionally a **separate package**
(`medzuch/jwt-bundle`), released from its own repository, so the core
library remains framework-agnostic.

## Why a separate package

- The core library has no Symfony dependency. Pulling in
  `symfony/framework-bundle` just to use plain JWT verification in a
  console script would be wasteful.
- Releasing the bundle on its own cycle lets us cut new bundle versions
  without retagging the core, and vice versa.
- The bundle can target multiple Symfony major versions independently of
  the core's PHP requirement.

## Target package layout

```
medzuch/jwt-bundle/
├── composer.json                  (requires medzuch/jwt-php: ^1, symfony/*: ^7.x)
├── src/
│   ├── MedzuchJwtBundle.php
│   ├── DependencyInjection/
│   │   ├── MedzuchJwtExtension.php
│   │   └── Configuration.php
│   ├── Security/
│   │   ├── JwtAuthenticator.php         (the Symfony Authenticator)
│   │   ├── JwtUserProvider.php          (interface)
│   │   ├── ClaimsBasedUserProvider.php  (sub claim → user)
│   │   └── JwtTokenExtractor.php        (Authorization: Bearer ...)
│   ├── Resources/config/services.php
│   └── Profile/                         (DI-friendly wrappers around core profiles)
└── tests/
```

## Configuration shape

```yaml
# config/packages/medzuch_jwt.yaml
medzuch_jwt:
    profiles:
        api_access_token:
            type: access_token      # → AccessTokenProfile
            issuer: 'https://issuer.example'
            audience: 'https://api.example'
            algorithms: ['RS256', 'ES256']
            leeway: '30 seconds'
            keys:
                source: jwks_uri
                uri: 'https://issuer.example/.well-known/jwks.json'
                cache:
                    pool: cache.app
                    ttl: 3600
        admin_id_token:
            type: id_token          # → IdTokenProfile
            issuer: 'https://accounts.google.com'
            audience: '%env(GOOGLE_CLIENT_ID)%'
            algorithms: ['RS256']
            keys:
                source: jwks_uri
                uri: 'https://www.googleapis.com/oauth2/v3/certs'
                cache:
                    pool: cache.app
```

Each profile becomes a public DI service named
`medzuch_jwt.profile.<name>`, typed as the appropriate consumer profile.

## Symfony Security integration

Wires into the Symfony 7 Security component as an
`AuthenticatorInterface`:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            custom_authenticators:
                - medzuch_jwt.authenticator.api_access_token
```

The bundle provides a per-profile authenticator service. The
authenticator:

1. Extracts the bearer token from the `Authorization` header (configurable
   extractor service per firewall).
2. Calls the profile's `parse()` method.
3. On success, constructs a `Passport` with the user fetched via the
   configured `JwtUserProvider`.
4. On failure, lets Symfony's normal failure handler do its job. The
   exception type is preserved so handlers can distinguish "expired" from
   "wrong audience" if they want.

## User provider shape

```php
interface JwtUserProvider extends UserProviderInterface
{
    public function loadUserFromClaims(ClaimsSet $claims): UserInterface;
}
```

A sensible default `ClaimsBasedUserProvider` is shipped which uses the
`sub` claim plus a configurable `roles_claim` (default: `roles` or
`scope` split on space).

## Testing

The bundle's test suite uses a kernel-based functional test
(`KernelTestCase`) that:

- Boots a minimal kernel with a sample firewall.
- Issues a real token via a fixture issuer (HS256 with a fixed key).
- Sends a request, verifies that the controller sees the right user.

This keeps the core library's unit tests free of Symfony-specific
plumbing.

## Symfony version policy

| Bundle major | Symfony | PHP | Status |
|--------------|---------|-----|--------|
| 1.x | 7.x | 8.3+ | Initial release alongside core v1.0.0 |
| 2.x | 7.x + 8.x | TBD | When Symfony 8.x ships |

We do **not** support Symfony 6.4 LTS. The benefit (LTS reach) is not
worth the maintenance cost of two configuration shapes.

## Release order

The bundle ships **after** the core library reaches v1.0.0 (end of
Phase 5). Until then, applications wanting Symfony integration can use
the core library directly inside a custom authenticator — about 50
lines of glue code, documented as a recipe in
[04-api-surface.md](04-api-surface.md).
