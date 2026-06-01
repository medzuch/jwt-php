# 12 — Decisions

A running log of design decisions that materially shape the library
beyond what individual commits explain. Each entry records the choice,
the alternatives considered, and the reasoning — so future maintainers
can revisit without re-deriving the trade-off from scratch.

Entries are ordered newest first.

## D-003 — RSA-based JWE deferred out of Phase 3

**Date:** 2026-05-25
**Status:** Decided
**Phase context:** Phase 3 (JWE, v0.3). The roadmap listed RSA-OAEP,
RSA-OAEP-256, and RSA1_5 (decrypt-only) among the key-management
algorithms. Before implementation, the decision was made to ship v0.3
without any RSA-based key management.

### Problem

PHP 8.3 + OpenSSL 3.x cannot perform **RSA-OAEP-256** (OAEP with a
SHA-256 hash and MGF1) through the bindings exposed to userland:

- `openssl_public_encrypt()` / `openssl_private_decrypt()` accept only
  `OPENSSL_PKCS1_OAEP_PADDING`, which is hardwired to SHA-1 for both the
  OAEP digest and MGF1. There is no parameter to select SHA-256.
- The EVP `EVP_PKEY_CTX_set_rsa_oaep_md` knob that OpenSSL exposes in C
  is not surfaced by PHP's `ext-openssl`.

This is the **same class of gap** that deferred RSA-PSS in
[D-002](#d-002--rsa-pss-ps256ps384ps512-deferred-out-of-phase-2): a JOSE
algorithm OpenSSL supports internally but PHP does not expose. RSA-OAEP
(SHA-1) and RSA1_5 *are* reachable natively, but RSA-OAEP-256 is the
variant modern issuers actually use.

### Alternatives considered

1. **Adopt `phpseclib/phpseclib` v3** for RSA key encryption. Unblocks
   RSA-OAEP-256 cleanly and would retroactively unblock PS\* (a D-002
   re-evaluation trigger). Costs three runtime dependencies and pivots
   the library's *"standalone, zero-runtime-deps"* identity (D-001).
2. **Hand-roll OAEP (MGF1 + EME-OAEP) on raw RSA.** ~150–250 LoC of
   security-critical padding code we own and audit forever — the exact
   objection that sank the hand-rolled EMSA-PSS in D-002.
3. **Ship only native RSA: RSA-OAEP (SHA-1) + RSA1_5-decrypt; defer
   RSA-OAEP-256.** Ships the weaker OAEP variant while omitting the one
   most deployments need — an awkward, half-complete RSA story.
4. **Defer all RSA-based JWE out of v0.3.** Ship the symmetric (`dir`,
   AES-KW, AES-GCM-KW) and ECDH-ES key management plus the full content-
   encryption set, all of which OpenSSL + libsodium cover natively with
   zero new dependencies. Revisit RSA when phpseclib is adopted library-
   wide or a `medzuch/jwt-rsa-jwe` extension hosts it.

### Decision

**Option 4.** No RSA-based key management in v0.3.

### Rationale

- Consistency with D-001/D-002: the standalone identity is a foundational
  stance, and adopting phpseclib for JWE is the same positioning pivot
  deferred for PS\* — it deserves a single deliberate decision, not an
  incidental adoption mid-phase.
- Shipping SHA-1 OAEP alone (option 3) is worse than shipping no RSA: it
  invites use of the weaker variant and still misses RSA-OAEP-256.
- The in-scope set is genuinely useful on its own. ECDH-ES (P-curves +
  X25519) covers modern asymmetric JWE; `dir`/AES-KW cover the symmetric
  cases. RFC 7516 §A.3 (A128KW + A128CBC-HS256) and the RFC 7520 symmetric/
  ECDH cookbook vectors all remain provable.
- A later extension package (or a library-wide phpseclib decision at
  Phase 4/5) can add the RSA family without forcing the dependency on
  consumers who don't need it.

### Consequences

- `docs/05-phased-roadmap.md` Phase 3: RSA-OAEP/-256 and RSA1_5 removed
  from deliverables; exit criterion #4 (RSA1_5 encrypt-path refusal)
  removed with them. A "Deferred out of Phase 3" section back-links here.
- `docs/03-rfc-compliance.md`: RSA-OAEP/-256 and RSA1_5 rows and RFC 8725
  §3.2 (RSA-PKCS1 v1.5) marked 🚫-deferred with a link here. RFC 7516
  §A.1/§A.2 (RSA vectors) are out; §A.3 becomes the headline conformance
  vector.
- `UnsafeAlgorithmException` (planned for the RSA1_5 encrypt-path refusal)
  is not introduced in v0.3 — no shipped algorithm has a refused direction.

### Re-evaluation triggers

- A library-wide decision to adopt phpseclib (e.g. for PS\* per D-002, or
  during Phase 4/5). RSA-OAEP-256 then rides in at marginal cost.
- PHP exposes the OAEP digest parameter in `ext-openssl` (mirrors the
  PSS trigger in D-002).
- A `medzuch/jwt-rsa-jwe` extension is built on the public algorithm
  interfaces and proves the boundary. Document the extension point in
  `docs/04-api-surface.md` and reference it here.

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
