# 14 — Performance

This library is built security-first, not benchmark-first. This page exists so
that "security-first" never quietly means "slow," and so the places where it
*does* cost something are measured, explained, and defensible rather than
hand-waved.

The short version: **where real public-key crypto dominates the work
(RS256/ES256 — the common case for OAuth/OIDC access and ID tokens), this
library is competitive with or faster than the established alternatives. Where
the crypto is near-free (HS256), our richer default validation shows up as
relative overhead** — but the absolute cost stays in the tens of microseconds.

## What was measured

A comparison against the three most widely used PHP JWT libraries:

- **medzuch/jwt-php** — this library.
- **firebase/php-jwt** `^7.0` — the de-facto default.
- **web-token/jwt-framework** `^3.4` — the full-featured JOSE suite.
- **lcobucci/jwt** `^5.0` — the other popular fluent-API library.

For each of **HS256 / RS256 / ES256**, two operations:

- **issue** — build the claim set and produce a signed compact JWS.
- **verify** — parse a compact JWS and check its signature.

Numbers are operations/second, higher is better; `×N` is throughput relative
to the fastest library in that row. Measured on PHP 8.3.31 (the dev container),
single-threaded, with `ext-gmp` present (see *Fairness* below). They are
**indicative, not a leaderboard** — micro-benchmarks on one machine. Re-run
them on your own hardware with `benchmarks/run.php`.

| Operation | medzuch | firebase | web-token | lcobucci |
|---|---|---|---|---|
| issue HS256  | 43k/s (×0.29) | 149k/s (×1.00) | 54k/s (×0.36) | 60k/s (×0.40) |
| verify HS256 | 9k/s (×0.11)  | 86k/s (×1.00)  | 43k/s (×0.50) | 59k/s (×0.69) |
| issue RS256  | 3k/s (×1.00)  | 2k/s (×0.59)   | 730/s (×0.27) | 1k/s (×0.56) |
| verify RS256 | 9k/s (×0.81)  | 10k/s (×0.93)  | 2k/s (×0.21)  | 11k/s (×1.00) |
| issue ES256  | 22k/s (×1.00) | 11k/s (×0.49)  | 12k/s (×0.54) | 9k/s (×0.41) |
| verify ES256 | 6k/s (×0.74)  | 6k/s (×0.74)   | 9k/s (×1.00)  | 7k/s (×0.86) |

The `medzuch` verify here runs the **full** consumer validation — algorithm
allow-list, keys, `iss`, `aud`, `typ`, and required-claim enforcement — i.e.
what `AccessTokenProfile::consumer` configures by default. The other libraries'
verify calls check the signature (firebase also `exp`/`nbf`); claim checks are
extra code you add. That asymmetry is deliberate and is the whole story below.

## How to read this: two regimes

**Asymmetric (RS256/ES256) — crypto dominates; we lead on issue, trail slightly
on verify.** An RSA-2048 signature or a P-256 ECDSA operation costs hundreds of
microseconds to ~a millisecond, dwarfing per-call framework overhead. This
library is the **fastest issuer** for both RS256 and ES256 (a lean signing
path). On **verify** it stays in the same cluster as the other `openssl`
libraries — ~9k/s RS256, ~6k/s ES256 — but sits a little *below* firebase and
lcobucci, because it does full claim validation in that call while they verify
the signature only (see the table below). All three `openssl` libraries pull
far ahead of web-token on RSA verify (×0.21), which does that arithmetic through
`brick/math`+gmp rather than `openssl`. This is the regime that matters for
production OAuth 2.0 / OIDC, where access and ID tokens are almost always RS256
or ES256 — and where this library is competitive on both sides.

**Symmetric (HS256) — crypto is near-free, so overhead is all you see.** An
HMAC-SHA-256 is a single fast hash. With the crypto cost gone, what remains is
whatever each library does *around* it — and that is where the libraries differ
in philosophy, not raw speed:

- **issue HS256**: ~23µs/op here vs firebase's ~7µs (lcobucci ~17µs, web-token
  ~18µs). The difference is the immutable builder, explicit `typ` handling, and
  header/claim assembly.
- **verify HS256**: ~110µs/op here vs firebase's ~12µs, lcobucci's ~17µs and
  web-token's ~23µs — the widest gap on the board (×0.11). It is also the most
  misleading number to read without context, because **the four libraries are
  not doing the same work**, which is the whole point of the next section.

## Why our verify does more (the defensible part)

On the verify path, the libraries validate different amounts by default:

| | signature | `exp`/`nbf` | `iss`/`aud` | `typ` | strict JOSE header / alg-confusion | EC point-on-curve |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| **medzuch/jwt-php** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| firebase/php-jwt | ✓ | ✓ | — | — | partial | — |
| web-token (`verifyWithKey`) | ✓ | — | — | — | — | on key load |
| lcobucci (`SignedWith`) | ✓ | — | — | — | — | — |

`firebase`'s `decode()` checks the signature plus `exp`/`nbf`/`iat`; it does
**not** check `iss` or `aud` (the caller must, afterwards). web-token's
`verifyWithKey()` and lcobucci's `SignedWith` constraint check **only the
signature** — any claim checking is a separate pipeline you assemble yourself
(web-token's `ClaimChecker`, lcobucci's additional `Constraint`s), not included
in these numbers.

This library's `Validator`, by contrast, does the full RFC 7519 / RFC 8725
job in that one timed call:

- strict compact-JWS parsing (base64url, JSON, structural checks);
- algorithm-confusion defence — the verifying algorithm comes from your
  allow-list, never from the token's `alg` header
  (see [02 — Threat Model](02-threat-model.md));
- `exp` / `nbf` with configurable leeway, required-claim enforcement,
  `iss` / `aud` / `typ` matching.

So "slower on HS256 verify" really means "does issuer, audience, type,
required-claim and strict-structural validation that the others defer to your
code." Add equivalent constraints to the others and the gap narrows sharply. And
the absolute figure — ~110µs — still means **~9,000 fully-validated tokens per
second on a single core**, which is not the bottleneck in any realistic service.

This validation is a roughly *constant* per-verify cost, so its visibility
depends entirely on what it sits next to. On HS256, where the hash is nearly
free, it is almost the entire measurement (×0.11). On RS256/ES256 it is a small
slice of the public-key math — enough to put us just behind the signature-only
verifiers (×0.81 on RS256 verify), not enough to leave the cluster. Either way
you are paying it *to get the validation*, not for nothing — and on the issue
side, where there is no such validation step, this library is the fastest of the
four for both RS256 and ES256.

Other defended-by-default work that shows up as cost elsewhere: EC public keys
are validated as on-curve when loaded (via OpenSSL's `EC_POINT_oct2point`), and
the curve is bound to the algorithm (RFC 7518 §3.4) so a P-384 key cannot be
used with ES256.

## Reproducing

The harness is an **isolated sub-project** under `benchmarks/` — its own
`composer.json` pulls the three competitors so they never touch this library's
own dependency tree. See [`benchmarks/README.md`](../benchmarks/README.md).

```bash
docker compose exec php sh -c 'cd /app/benchmarks && composer install'
docker compose exec php php benchmarks/run.php
# longer budget per op for tighter numbers:
docker compose exec php env BENCH_BUDGET=3.0 php benchmarks/run.php
```

### Fairness: `ext-gmp` is required for web-token

web-token/jwt-framework performs RSA/EC arithmetic through `brick/math`, which
is **~2000× slower in pure PHP than with `ext-gmp`** (an RSA-2048 sign measured
at 2.7s without it). This library, firebase/php-jwt, and lcobucci/jwt use
`ext-openssl` directly and are unaffected. The dev image therefore ships `ext-gmp` **solely so
web-token is measured fairly** — it is not a dependency of this library. Running
the benchmark without GMP would produce a meaningless ~1000× "win" that reflects
a missing extension, not the libraries.

## Caveats

- Micro-benchmarks on a single machine and PHP build. Treat the `×N` factors as
  "same ballpark / clearly faster / clearly slower," not as precise ratios.
- The verify rows compare each library's idiomatic happy-path call; as the table
  above shows, those calls do **different amounts of validation**. That
  asymmetry is the finding, not a flaw in the measurement.
- No JIT and no opcache preloading are configured; production deployments with
  opcache will see higher absolute throughput across all four libraries.
