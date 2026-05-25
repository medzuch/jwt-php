# 12 — Decisions

A running log of design decisions that materially shape the library
beyond what individual commits explain. Each entry records the choice,
the alternatives considered, and the reasoning — so future maintainers
can revisit without re-deriving the trade-off from scratch.

Entries are ordered newest first.

## D-002 — RSA-PSS (PS256/PS384/PS512) deferred out of Phase 2

**Date:** 2026-05-24
**Status:** Decided
**Phase context:** Phase 2 originally listed PS256/PS384/PS512 alongside
ES* and EdDSA. After implementation work began, the decision was made
to drop PS* from v0.2.

### Problem

PHP 8.3 + OpenSSL 3.x does not expose RSASSA-PSS through
`openssl_sign()`:

- No PSS-related algorithm name (`RSA-PSS-SHA256`, `id-RSASSA-PSS`,
  `sha256WithRSAPSS`, …) is accepted; all return *"Unknown digest
  algorithm"*.
- `OPENSSL_PKCS1_PSS_PADDING` is not defined as a PHP constant.
- `openssl_private_encrypt()` with the PSS padding constant value (`6`)
  rejects the operation.

That leaves only two production-quality paths.

### Alternatives considered

1. **Hand-rolled EMSA-PSS + raw RSA.** Implement RFC 8017 §9.1.1 /
   §9.1.2 (EMSA-PSS-ENCODE / -VERIFY) and MGF1 in pure PHP, feed the
   encoded message through `openssl_private_encrypt` /
   `openssl_public_decrypt` with `OPENSSL_NO_PADDING`. About 250 lines
   of security-critical crypto we'd own and audit forever. A working
   implementation, with bidirectional `openssl dgst` interop tests and
   RFC 7520 §4.2 verify-only conformance, was built and reviewed (see
   the closed PR
   [#10](https://github.com/medzuch/jwt-php/pull/10)).

2. **`phpseclib/phpseclib` v3.** Delegate to a mature, widely-deployed
   pure-PHP crypto library. Three lines of fluent setup per algorithm.
   Lowers our crypto-audit surface to zero for PSS. Adds three runtime
   dependencies (`phpseclib/phpseclib`, `paragonie/random_compat`,
   `paragonie/constant_time_encoding`) — meaningful given the library
   advertises *"standalone, modern JWT library for PHP 8.3+"* with zero
   runtime deps beyond `psr/clock`.

3. **Defer to a later release.** Ship v0.2 with ES + EdDSA + profiles;
   revisit PS* when (a) PHP/OpenSSL bindings expose PSS natively, or
   (b) a separate `medzuch/jwt-pss` extension package can host it
   without dragging dependencies into the core library.

### Decision

**Option 3.** PSS is not in v0.2.

### Rationale

- The library's identity is *standalone* (README opening line,
  composer.json with zero runtime deps beyond `psr/clock`). Adopting
  phpseclib for one algorithm family pivots that positioning, and the
  same question would resurface at Phase 3 (JWE) for several more
  algorithms PHP/OpenSSL expose inconsistently. That broader decision
  deserves its own dedicated review when the time comes, not an
  incidental adoption to unblock a single signature scheme.
- Hand-rolling 250 LoC of crypto means owning a permanent audit
  surface. The implementation works and tests well, but every future
  RFC clarification, Wycheproof finding, or OpenSSL behaviour change
  is our responsibility forever.
- PS* matters most for OAuth 2.0 deployments that mandate it, but
  RS* and ES* cover the dominant share of issuers (Google, Auth0,
  Keycloak default to RS256; modern issuers ship ES256). v0.2 is
  still usable for the vast majority of consumers without PS*.
- A separate `medzuch/jwt-pss` package can later depend on phpseclib
  (or any other crypto backend) without forcing that choice on every
  consumer of the core library. Users who need PS* opt in by adding a
  second package; users who don't aren't billed for the dependency.

### Consequences

- `docs/05-phased-roadmap.md` Phase 2 deliverables: PS* removed; an
  explicit "Deferred" section names the deferral with a back-link
  here.
- `docs/03-rfc-compliance.md` RFC 7518 §3.5 PS rows: mark as
  🚫-with-rationale (replaced from the implicit 🚧 Phase 2 they
  carried).
- Phase 5 mutation-testing target (MSI ≥ 95% on `src/Algorithm/`)
  remains as is — PS* never enters the source tree.
- PR #10 closed without merge; the hand-rolled EMSA-PSS history
  remains in the closed-PR record for future implementers to
  reference.

### Re-evaluation triggers

- PHP 8.5+ adds first-class PSS support in `openssl_sign` /
  `openssl_verify` (an RFC has been floated upstream). If accepted,
  bringing PS* in via the native bindings becomes free of all
  trade-offs above — revisit.
- A `medzuch/jwt-pss` extension package is built externally and
  proves the boundary works. Document the extension point in
  `docs/04-api-surface.md` and reference it here.
- The Phase 3 JWE work concludes that phpseclib (or another crypto
  library) is necessary anyway. At that point, PS* riding in alongside
  becomes a small incremental cost rather than a positioning shift.

## D-001 — Library identity is "standalone, zero-runtime-deps"

**Date:** Initial commit
**Status:** Decided (foundational)

`composer.json` has exactly one runtime dependency beyond PHP
extensions: `psr/clock`. All other PSR integrations are listed under
`suggest`, opt-in only. Crypto is OpenSSL (`ext-openssl`) for RSA/EC
and libsodium (`ext-sodium`) for Ed25519. This is a deliberate stance
documented in the README opening line and reinforced by the
`roave/security-advisories` dev dependency that blocks installs with
known-vulnerable transitive packages.

Implication: every dependency proposal is a foundational decision, not
a routine `composer require`. The cost of adding a runtime dependency
must be paid against this baseline. See D-002 for a worked example.
