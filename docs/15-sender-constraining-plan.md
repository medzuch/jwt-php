# 15 — Sender-constrained tokens (proposal)

**Status: proposal, not adopted.** Nothing here is scheduled. It exists because
§3.6 of `medzuch/jwt-bundle`'s
[`docs/plan.md`](https://github.com/medzuch/jwt-bundle/blob/main/docs/plan.md)
lists four standards-track rows, and the Phase 5+ note in its §7 says of the
ones still open that they "begin as library work". This document is the
library's answer to what that work actually is — including the parts that are
not ours.

> **The short version.** Two of the four rows need a small, well-bounded
> addition here: the *confirmation primitives* (RFC 7638 thumbprints and their
> `cnf` counterpart). One needs a new profile that is genuinely token-library
> work (the DPoP proof JWT). One needs nothing from us at all, and one needs
> almost nothing. The confirmation primitives are worth doing on their own
> merits whether or not anything else follows.

## What the bundle asked for

| Bundle row | What it needs from here | Verdict |
|---|---|---|
| DPoP (RFC 9449) | An RFC 7638 thumbprint, a typed `cnf`, and a way to verify the proof JWT | Real library work — Phases A and B |
| mTLS-bound tokens (RFC 8705) | An `x5t#S256` thumbprint and the same typed `cnf` | Real library work — Phase A alone |
| Token exchange (RFC 8693) | Two claims and nothing else | Phase C — almost nothing |
| Introspection fallback (RFC 7662) | An HTTP client | Not ours. Ever |

The cookbook (§4, §5) already documents both bindings as recipes that assemble
`cnf` by hand with `withClaim()`. That was the right call for v1.0 and it is not
wrong now. What it cannot do is compute a thumbprint, and that is the whole of
the gap for mTLS.

## Phase A — confirmation primitives

The centre of both bindings is one operation the library cannot currently
perform: hash a key the way RFC 7638 says to.

**This phase is ~150 lines and closes the mTLS row completely.** Everything it
needs already exists. `Key::toJwk(): array` is abstract on the base class and
implemented by every key type; `Primitives\Json::encode()` already emits with
`JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` and no whitespace;
`Primitives\Base64Url` and `Primitives\ConstantTime` are there. Assembling
those four against the worked example in RFC 7638 §3.1 reproduces the
specified thumbprint `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs` exactly —
measured in this repository before this document was written, not assumed.

### A1 — `Key\Thumbprint`

```php
final class Thumbprint
{
    public static function of(Key $key): string;          // RFC 7638, SHA-256, base64url
    public static function matches(Key $key, string $expected): bool;
}
```

**The one trap, and it is a silent one.** `toJwk()` returns more than the
thumbprint may see. For an RSA public key it emits `kty, alg, n, e, kid` — and
RFC 7638 §3.2 admits *only the required members*, lexicographically ordered.
An implementation written as `hash('sha256', Json::encode($key->toJwk()))` is
one line, looks obviously correct, and produces a thumbprint that matches
nothing. The required sets are fixed and small:

| `kty` | Members, in order |
|---|---|
| `RSA` | `e`, `kty`, `n` |
| `EC` | `crv`, `kty`, `x`, `y` |
| `OKP` | `crv`, `kty`, `x` |
| `oct` | `k`, `kty` |

`matches()` exists so callers compare through `ConstantTime::equals()` rather
than `===`. A thumbprint is not a secret, but it is an authorization decision,
and the cookbook already tells readers to use `hash_equals()` here.

**`oct` is in the table but should not be reachable.** RFC 7638 defines a
thumbprint for symmetric keys, and computing one means hashing the secret
itself. There is no confirmation method that wants it — `cnf.jkt` is by
definition a public key — so `of()` should refuse a `SymmetricKey` rather than
quietly digest key material that was never meant to leave the process. The row
stays in the table because an implementation has to know the required set
exists; it does not stay in the API.

### A2 — `Key\CertificateThumbprint`

RFC 8705 §3.1: the base64url-encoded SHA-256 of the DER encoding of the client
certificate.

```php
final class CertificateThumbprint
{
    public static function ofDer(string $der): string;
    public static function ofPem(string $pem): string;    // strips armour, decodes, delegates
}
```

`ofPem()` earns its place because what a reverse proxy forwards in
`X-SSL-CLIENT-CERT` is PEM, sometimes URL-encoded, and getting from there to
DER is exactly the step an application gets wrong quietly.

### A3 — `Jwt\Confirmation` and a typed accessor

```php
final class Confirmation
{
    public static function jwkThumbprint(string $jkt): self;
    public static function certificateThumbprint(string $x5tS256): self;
    public function jkt(): ?string;
    public function x5tS256(): ?string;
    public function toClaim(): array;
}
```

with `ClaimsSet::confirmation(): ?Confirmation` beside it. Today `cnf` is
reachable only as `$claims->get('cnf')` — `mixed`, and every caller writes the
same `is_array()` dance the cookbook currently shows.

**The accessor must not be fail-closed.** RFC 7800 §3.1 requires that "all
confirmation members that are not understood by implementations MUST be
ignored", so a `cnf` carrying `jwe`, `jku`, `kid` or anything a future
specification adds has to parse to a `Confirmation` that simply answers `null`
for the members we model — never an exception. Reading somebody else's token is
where this bites: a relying party that throws on an unfamiliar `cnf` member
rejects tokens the standard says it should accept.

The named constructors give one member each, which is the right shape: the same
section says the claim "MUST represent only a single proof-of-possession key;
thus, at most one of the `jwk`, `jwe`, and `jku` confirmation values defined
below may be present". `jkt` and `x5t#S256` are later additions that restriction
does not literally name, but a token bound to both a DPoP key and a client
certificate is two keys, and nothing in RFC 9449 or RFC 8705 asks for it.

### A4 — issuing side

`AccessTokenBuilder::confirmedBy(Confirmation)`, so the issuing half stops
being `->withClaim('cnf', ['jkt' => $jkt])`. Same for `IdTokenBuilder` only if
a use appears; RFC 9449 binds access tokens.

**After Phase A the bundle's mTLS row is unblocked entirely**, and its DPoP row
is unblocked on the issuing side. No further phase is required for either.

## Phase B — the DPoP proof profile

Verifying a DPoP proof is a JWT operation, so it belongs here rather than in
the bundle. It is also the only part of DPoP that does: `htm`/`htu` comparison
and `jti` replay are protocol, and the cookbook is right to say so.

Four things are missing, and two of them are interesting.

### B1 — `MediaType::dpopProof()`

`dpop+jwt`, required by RFC 9449 §4.2. `MediaType::custom('dpop+jwt')` already
works; a named constructor puts it beside `accessToken()` and `idToken()` and
takes the string out of application code.

### B2 — `Key\Resolver\HeaderJwkResolver` — **the one that needs a decision**

A DPoP proof carries its own verification key in the `jwk` header. No resolver
in this library reads that member, and the reason is structural rather than
written down: `KeyResolver::resolve(array $header): Key` is handed the header
and every implementation goes elsewhere for the key, because a token that names
its own key proves nothing. Worth noting while planning this — [02 — Threat
Model](02-threat-model.md) does not currently mention the `jwk` header at all, so the rule this phase makes
an exception to is one the documentation has never actually stated.

DPoP is the exception that works, but only because of what happens *after*:
the proof's key is trusted for nothing until its thumbprint is compared to the
access token's `cnf.jkt`, which came from the authorization server. The
resolver is safe **only** under that binding, and there is no way for the
resolver itself to check that it happened.

So: ship it, name it so nobody reaches for it by accident, refuse private key
material (RFC 9449 §4.3 requires this), refuse symmetric keys, and write the
constraint in the class docblock and in [02 — Threat Model](02-threat-model.md)
rather than in a release note. This wants a `D-004` in
[12 — Decisions](12-decisions.md) — it is the first
deliberate exception to a rule the architecture states flatly, and a reader
who finds the class without the reasoning will assume the rule was softer than
it is.

### B3 — `ValidatorBuilder::expectIssuedWithin(DateInterval)`

**A gap worth fixing regardless of DPoP.** `Validator` checks `iat` in one
direction only: `IssuedInFutureException` when it is ahead of the clock.
Nothing rejects an `iat` that is arbitrarily old. Measured: a proof carrying
`typ: dpop+jwt`, `jti`, `htm`, `htu` and an `iat` of one year ago validates
today, through `expectType()` and `requireClaims()`, without complaint.

For ordinary tokens `exp` covers this. A DPoP proof has no `exp` — RFC 9449
§4.3 asks instead that the creation time be "within an acceptable window", and
there is currently no way to say that. `expectIssuedWithin()` is that way, and
it is a general validator capability, not a DPoP one: the bundle's own plan
already lists "max token age" among the post-validation policy it has to apply
itself, precisely because we do not offer it. That is a second consumer before
the first one is written.

Two questions to settle when it is designed, both easy to get wrong silently:

- **Is a missing `iat` an error once a window is set?** RFC 9449 §4.2 makes
  `iat` required in a proof, so for that profile it must be; for an ordinary
  token `iat` is optional and a window should probably not conjure a
  requirement the caller did not ask for. Whichever way it goes, the builder
  method is the place the answer is written down.
- **Does the window respect `withLeeway()`?** Every other time-based check
  does. A window that ignores leeway will reject proofs from a client whose
  clock is inside the tolerance the same validator already forgives elsewhere.

### B4 — `Profile\DpopProofProfile` / `DpopProofConsumer`

```php
$result = DpopProofProfile::consumer(
    algorithms: [new Es256()],
    window: new DateInterval('PT1M'),
)->verify(
    proof: $dpopHeader,
    method: 'GET',
    url: 'https://api.example.com/resource',   // compared without query or fragment
    accessToken: $bearer,                       // when present, `ath` is checked
    nonce: $issuedNonce,                        // when the server issued one
);

$result->thumbprint();   // RFC 7638 of the proof's own key — compare to cnf.jkt
$result->jwtId();        // for the caller's replay store
```

Checks, per RFC 9449 §4.3: `typ` is `dpop+jwt`; `alg` is asymmetric,
registered and allowed (never `none`, never HMAC); `jwk` is present, public and
carries no private material; the signature verifies under that key; `htm`
equals the method; `htu` equals the URI after normalisation, with query and
fragment removed; `iat` is inside the window; `jti` is present; `ath` equals
the base64url SHA-256 of the access token when one is presented; `nonce`
matches when one was issued.

`htu` is compared after RFC 3986 §6 normalisation, with query and fragment
removed — a comparison of raw strings would refuse a client that spelled a
default port or percent-encoding differently from the server.

A missing `nonce` where one was issued is the one failure that is **not** a
validation error. RFC 9449 answers it with a `use_dpop_nonce` response carrying
a fresh nonce, which is a protocol move the resource server makes, not an
exception a parser throws. The consumer reports it as its own outcome and lets
the caller respond; the same boundary this document draws everywhere else.

What it deliberately does **not** do is remember `jti`. Which brings us to:

### B5 — `ReplayStore`, an interface and nothing else

RFC 9449 §4.3 requires that a server track `jti` values "for the time window in
which the respective DPoP proof JWT would be accepted". That is a store, and a
store is state, and state has no place in a library whose identity is
"standalone, zero-runtime-deps" (`D-001`).

Name the operation, ship no implementation:

```php
interface ReplayStore
{
    /** True when this identifier had not been seen; false when it had. */
    public function claim(string $jti, DateTimeImmutable $until): bool;
}
```

One method, and it returns a boolean rather than throwing, because the check
and the record have to be one operation: between a `seen()` and a `remember()`
is where a proof gets accepted twice. `medzuch/jwt-bundle` reached the same
conclusion for refresh tokens in its 1.2.0, where
`RefreshTokenStoreInterface::consume()` spends a token and reports a previous
spend in a single call for exactly this reason.

**Its `TokenDenylistInterface` is the opposite shape, and that is not an
inconsistency.** That one splits the operation — `revoke(string $jti,
DateTimeImmutable $until): void` beside `isRevoked(string $jti): bool` — and
splitting is fine there, because revocation is monotonic: a token revoked stays
revoked, two concurrent revocations of the same `jti` agree, and a check that
races a write is merely early. A `jti` claim is not monotonic. Two concurrent
presentations of one proof must produce one success and one failure, and only
an operation that decides and records together can say which is which.

So `D-005` is worth writing not because three interfaces agree, but because
two of them differ and the difference is easy to get backwards: **state that
answers "has this happened" may be split; state that answers "may I be the one
to do this" may not.**

`DpopProofConsumer` takes an optional `ReplayStore`; given none, it verifies
everything else and says so in the docblock rather than pretending.

## Phase C — what stays out, and why

**Token exchange (RFC 8693).** The grant is an HTTP endpoint: a POST, a set of
parameters, a response. None of that is a token library's work. The library's
entire share is two claims — `act` (§4.1) and `may_act` (§4.4) — which
`withClaim()` already writes and `ClaimsSet::get()` already reads. If delegation
turns out to be common, a typed `ActorClaim` beside `Confirmation` is the whole
of it. **The bundle's plan is wrong to say this row begins as library work**,
and that sentence should be corrected in its [plan](https://github.com/medzuch/jwt-bundle/blob/main/docs/plan.md) whatever else
happens.

**Client credentials helpers.** §3.6 puts these in the same bullet as token
exchange, together with "an outbound `HttpClient` decorator that attaches a
cached machine token to internal API calls". The answer is the same and shorter:
minting a machine token is `AccessTokenProfile::issuer()` today, and caching one
against an outbound HTTP client is neither a token nor a library concern.

**Introspection (RFC 7662).** A POST to the authorization server and a JSON
response, for tokens that are not JWTs at all. It needs an HTTP client, which
this library does not have and must not acquire — `D-001` is the reason the
package is worth using. Nothing here. Not a deferral: a boundary.

## Ordering, and what each phase buys

| Phase | Size | Unblocks |
|---|---|---|
| A | ~150 lines, one conformance vector | mTLS entirely; DPoP's issuing half |
| B3 | ~20 lines | Nothing by itself, but fixes a real validator gap |
| B1, B2, B4, B5 | A profile plus a resolver | DPoP's verifying half |
| C | Nothing | — |

**A is worth doing alone.** It closes a whole row for the bundle, it is small,
every piece it needs already exists, and it has an RFC-supplied test vector to
prove it right. B is a coherent unit but a larger one, and it carries the only
security-architecture decision in this document.

## Documentation and tests this would move

- [01 — Architecture](01-architecture.md) — the out-of-scope list gains introspection and the
  token-exchange grant, and loses nothing.
- [02 — Threat Model](02-threat-model.md) — state the rule first (an embedded `jwk` is not a key
  source), then the exception a DPoP proof makes and what makes it safe. The
  rule is absent today, which is why the exception cannot be written without it.
- [03 — RFC Compliance](03-rfc-compliance.md) — RFC 7638, RFC 9449, RFC 8705 rows.
- [04 — Public API Surface](04-api-surface.md) — `Thumbprint`, `CertificateThumbprint`, `Confirmation`,
  `ReplayStore`, `DpopProofProfile`, `HeaderJwkResolver`, and the two new
  builder methods.
- [05 — Phased Roadmap](05-phased-roadmap.md) — a Phase 7. The roadmap currently ends at Phase 6
  ("PHP version support"), so there is no post-1.0 feature phase to add these
  to.
- [12 — Decisions](12-decisions.md) — `D-004` (header `jwk` is an exception, not a relaxation)
  and `D-005` (stateful protocol needs are interfaces here, never
  implementations).
- [13 — Cookbook](13-cookbook.md) §4 and §5 — rewritten to call the new API instead of
  assembling `cnf` by hand. The recipes stay; they stop carrying cryptography.
- `tests/Conformance/` — `Rfc7638Section31Test` (the worked example above) and
  a `Rfc9449` proof-validation suite.
- `tests/Property/` — thumbprint stability across a round trip through
  `fromJwk()`/`toJwk()`, and across PEM and JWK constructions of one key.

## What this is not

It is not full DPoP. The authorization-server half — issuing a nonce, the
`DPoP-Nonce` header, `use_dpop_nonce` errors — is protocol, and belongs where
the token endpoint is. It is not an OAuth framework. And it is not a
commitment: the four rows came from another package's roadmap, and the answer
to two of them is that they were never ours.
