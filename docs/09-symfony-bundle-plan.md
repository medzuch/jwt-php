# 09 — Symfony Bundle (companion package)

The Symfony integration lives in a **separate package**,
[`medzuch/jwt-bundle`](https://github.com/medzuch/jwt-bundle), released from its
own repository so this library stays framework-agnostic.

> **This document is the library-side view only.** The bundle's architecture,
> configuration tree, service wiring and roadmap are designed and versioned in
> the bundle's own repo — see its `docs/plan.md`. What follows is what
> *maintainers of this library* need to know: why the split, which parts of our
> public surface the bundle depends on, and what we owe it.
>
> The pre-1.0 sketch that used to fill this page (a bespoke `JwtAuthenticator`,
> a `JwtUserProvider` interface, `MedzuchJwtExtension`/`Configuration` classes,
> a `profiles:` config tree) is **superseded**. It predated Symfony's native
> `access_token` authenticator and `AbstractBundle`, both of which the bundle
> now builds on. Do not treat anything below as a spec for the bundle's shape.

## Why a separate package

- This library has no Symfony dependency. Pulling in
  `symfony/framework-bundle` just to verify a JWT in a console script or a
  non-Symfony service would be wasteful.
- Independent release cycles: bundle fixes ship without retagging the core, and
  core releases don't wait on framework integration work.
- The bundle can track Symfony's supported-version window (which moves roughly
  yearly) independently of this library's PHP floor.

## What the bundle does

It wires our profiles into Symfony's Security stack, DI, console and profiler,
so an app can act as a resource server (verify bearer tokens on a firewall), an
authorization server (mint access tokens at login), an OIDC relying party
(verify a third-party IdP's tokens via cached JWKS), or all three. The
integration point is Symfony's own `AccessTokenHandlerInterface`; the bundle
does no crypto and no claim validation of its own.

**Consequence for us:** any behaviour the bundle would need that involves
parsing, validating, or key resolution belongs *here*, not there. The bundle is
allowed to be a thin adapter only if this library exposes what it needs.

## Library surface the bundle depends on

All of it is public and frozen under the
[04 — Public API Surface](04-api-surface.md#stability-promise) stability
promise, so none of it can change within 1.x. Treat the bundle as a named
downstream consumer during BC review:

| Area | Types |
|---|---|
| Profiles | `AccessTokenProfile`, `IdTokenProfile`, `SetProfile` and their builder/consumer types; `ProfileConsumer::parse(): ClaimsSet` |
| Claims | `ClaimsSet` accessors (`subject()`, `audience()`, `getString()`, `getList()`, `all()`) |
| Keys | `HmacKey`, `RsaPrivateKey`/`RsaPublicKey::fromPem()`, `EcPrivateKey`, `OkpPrivateKey`, `JwkParser`, `JwkSet`, `KeyUse` |
| Key resolution | `KeyResolver`, `StaticJwkSetResolver`, `RemoteJwksResolver`, `CompositeResolver` |
| Algorithms | `SigningAlgorithm` implementations (`Hs256`…`Hs512`, `Rs256`…`Rs512`, `Es256`…`Es512`, `EdDsa`) |
| Types | `MediaType` (incl. `custom()`), `ValidatorBuilder` for app-defined profiles |
| Cross-cutting | PSR-20 `SystemClock`/`FrozenClock`, `SecurityLog`/`LogLevels`, the `JwtException` hierarchy |

The exception hierarchy matters more than it looks: the bundle maps our
exception *types* onto Symfony's 401 handling and RFC 6750
`WWW-Authenticate` error codes, and onto metrics that distinguish "expired"
from "bad signature" from "wrong audience". Collapsing or renaming exception
classes would be a bundle-visible break even if the messages stayed the same.

## Library-side backlog the bundle needs

Concrete gaps found while designing the bundle. None is urgent for 1.0
consumers of this library directly; all three affect what the bundle can offer.
(A fourth — roadmap-phase wording in docblocks and `composer.json` implying
`RemoteJwksResolver` had not shipped yet — is already fixed.)

1. **Clock leeway is unreachable through the profile factories.**
   `ValidatorBuilder::withLeeway()` exists, but none of
   `AccessTokenProfile::consumer()`, `IdTokenProfile::consumer()` or
   `SetProfile::consumer()` accepts a leeway argument. An app that needs skew
   tolerance must abandon the profile factory and hand-build a `ValidatorBuilder`
   — losing the profile's `typ` pinning and required-claim set, which is exactly
   the wrong trade. Fix: an appended optional `?DateInterval $leeway = null`
   parameter on the three factories (appending is BC-safe; inserting is not).
2. **Profile consumers accept a single audience.**
   `ValidatorBuilder::expectAudience()` already takes `string|array`, but
   `AccessTokenProfile::consumer()` narrows to `string $expectedAudience`.
   Multi-audience resource servers (one API verifying tokens minted for several
   audiences) can't be expressed. Fix: widen the parameter to `string|array`
   — a widening on an input type, so BC-safe.
3. **No passphrase-protected PEMs.** `RsaPrivateKey::fromPem()` calls
   `openssl_pkey_get_private($pem)` with no passphrase argument, so an
   encrypted private key cannot be loaded at all (same for `EcPrivateKey`).
   Shipping key files encrypted at rest is ordinary operational practice, and
   the bundle's PEM key source inherits the limitation. Fix: an appended
   optional `?string $passphrase = null`, passed through to OpenSSL — BC-safe,
   and the parameter must never be logged or echoed in exception messages.
4. **The PHP constraint caps below 8.4.** `"php": "~8.3.0"` means the bundle
   cannot support PHP 8.4 no matter what it declares. Symfony 7.x runs on 8.4
   widely, so this will bite the bundle before it bites us. Fix: verify on 8.4
   in CI and relax to `~8.3.0 || ~8.4.0` (or `>=8.3`).

## Version & release policy

The old gate — "the bundle ships after the core reaches v1.0.0" — is satisfied:
the core froze its API at [1.0.0](../CHANGELOG.md) (2026-06-11), so the bundle
can develop against a stable surface and require `medzuch/jwt-php: ^1.0`.

Which Symfony versions the bundle supports is **the bundle's decision**, made in
its own repo. This document previously ruled out Symfony 6.4 LTS unilaterally on
the grounds of "two configuration shapes"; that rationale is weaker than it
looked (the APIs the bundle uses barely diverge between 6.4 and 7.x), and the
call belongs where the maintenance cost lands. The only hard constraint we
impose is the PHP floor — 8.3+, and see backlog item 4 above about the ceiling.

## Testing boundary

Kernel-based functional tests (boot a minimal kernel, mint a real HS256 token,
send a request, assert the controller sees the right user) live in the
**bundle's** suite. This library's tests stay free of Symfony plumbing; the only
Symfony package in our `require-dev` is `symfony/http-client`, and only as a
PSR-18 implementation for `RemoteJwksResolver` tests.

## Using this library in Symfony without the bundle

Still fully supported, and the right choice for an app that wants one
authenticator and no configuration layer: the core drops into a custom
authenticator in about 50 lines. See
[13 — Cookbook § The core library inside a Symfony authenticator](13-cookbook.md#6-the-core-library-inside-a-symfony-authenticator).
