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
consumers of this library directly; each affects what the bundle can offer.
Items are kept once fixed, with the release that fixed them, so the bundle can
read the minimum core version it needs off this list. (A fifth — roadmap-phase
wording in docblocks and `composer.json` implying `RemoteJwksResolver` had not
shipped yet — is already fixed.)

**All four are fixed as of 1.1.0**, so a bundle requiring
`medzuch/jwt-php: ^1.1` needs no library-side work that is currently known.
New gaps belong here as they are found.

1. **Clock leeway was unreachable through the profile factories** — **fixed in
   1.1.0** ([#39](https://github.com/medzuch/jwt-php/issues/39)).
   `ValidatorBuilder::withLeeway()` existed, but none of
   `AccessTokenProfile::consumer()`, `IdTokenProfile::consumer()` or
   `SetProfile::consumer()` accepted a leeway argument, so an app needing skew
   tolerance had to abandon the profile factory and hand-build a
   `ValidatorBuilder` — losing the profile's `typ` pinning and required-claim
   set, exactly the wrong trade. All three now take an appended optional
   `?DateInterval $leeway = null` (appended, not inserted, to stay BC), passed
   through to `withLeeway()`. The bound is inherited rather than re-implemented:
   `ValidatorBuilder` rejects a negative interval and anything above
   `LEEWAY_CEILING_SECONDS` (300), which answers the issue's "consider an upper
   bound" note — the bundle can map its `leeway` config key straight through and
   let an out-of-range value fail loudly at wiring time.
2. **Profile consumers accepted a single audience** — **fixed in 1.1.0**
   ([#40](https://github.com/medzuch/jwt-php/issues/40)).
   `ValidatorBuilder::expectAudience()` always took `string|array`, but
   `AccessTokenProfile::consumer()` narrowed it back to
   `string $expectedAudience`, so multi-audience resource servers could not be
   expressed. The parameter is now `string|non-empty-list<string>`, forwarded
   unchanged — a widening on an input type, so BC. One addition beyond the
   issue: an empty list is refused with a `LogicException` instead of reaching
   `expectAudience([])`, which the builder reads as "no expected audiences" and
   would silently switch the check off — the failure mode a bundle mapping a
   YAML `audience: []` key would otherwise hit. `IdTokenProfile::consumer()`
   keeps `string $clientId`: OIDC ties an ID token to exactly one client, so
   that is single by design, not by omission.
3. **No passphrase-protected PEMs** — **fixed in 1.1.0**
   ([#41](https://github.com/medzuch/jwt-php/issues/41)).
   `RsaPrivateKey::fromPem()` and `EcPrivateKey::fromPem()` called
   `openssl_pkey_get_private($pem)` with no passphrase argument, so a key
   encrypted at rest could not be loaded at all. Both now take an appended
   optional `?string $passphrase = null`. The secret is never stored on the key
   object and never interpolated into a message; the local copy is wiped with
   `sodium_memzero()` once OpenSSL has consumed it, while the caller's own
   string is deliberately left intact. A wrong passphrase fails as
   `InvalidKeyException`, same type and leading message as a malformed PEM.
   **Note for the bundle's PEM key source:** an encrypted PEM supplied with
   *no* passphrase used to make OpenSSL prompt on the terminal ("Enter PEM
   pass phrase:"), which hangs any process with a tty — a boot-time deadlock
   dressed up as a slow start. That is fixed here too; it now fails cleanly.
4. **The PHP constraint capped below 8.4** — **fixed in 1.1.0**
   ([#42](https://github.com/medzuch/jwt-php/issues/42)). `"php": "~8.3.0"` allowed
   8.3.x only, so the bundle could not support PHP 8.4 no matter what it
   declared. The constraint is now `~8.3.0 || ~8.4.0`, matching a CI matrix
   that runs static analysis and the full suite on both minors; the explicit
   form was chosen over
   `>=8.3` so the constraint never promises a minor nobody has tested. The
   bundle is free to require 8.4 on its own if it wants to — our floor stays
   8.3 until it leaves security support.

## Version & release policy

The old gate — "the bundle ships after the core reaches v1.0.0" — is satisfied:
the core froze its API at [1.0.0](../CHANGELOG.md) (2026-06-11), so the bundle
can develop against a stable surface and require `medzuch/jwt-php: ^1.0`.

Which Symfony versions the bundle supports is **the bundle's decision**, made in
its own repo. This document previously ruled out Symfony 6.4 LTS unilaterally on
the grounds of "two configuration shapes"; that rationale is weaker than it
looked (the APIs the bundle uses barely diverge between 6.4 and 7.x), and the
call belongs where the maintenance cost lands. The only hard constraint we
impose is the PHP window — 8.3 and 8.4, both in CI (backlog item 4). The bundle
may narrow that (require 8.4 only) but cannot widen it.

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
