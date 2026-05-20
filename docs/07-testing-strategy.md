# 07 — Testing Strategy

For a cryptography library, tests are not a quality nice-to-have — they
are the load-bearing evidence that the code does what it claims. This
document describes the testing pyramid for this project.

## Three test suites

PHPUnit is configured with three suites in `phpunit.xml.dist`:

| Suite | Path | Purpose | Speed |
|-------|------|---------|-------|
| `unit` | `tests/Unit` | Isolated unit tests, one class per file. | Fast (<5s) |
| `integration` | `tests/Integration` | Multi-component, JWS round-trips, key resolvers. | Medium (~30s) |
| `conformance` | `tests/Conformance` | RFC test vectors, the McLean/Sanso PoCs. | Fast |

Run them separately:

```bash
composer test:unit
composer test:integration
composer test:conformance
```

Or all at once:

```bash
composer test
```

## Coverage targets

- Overall line coverage on `src/`: **≥ 95%**.
- `src/Algorithm/` and `src/Primitives/`: **100%**.
- `src/Jws/` and `src/Jwe/`: **≥ 98%**.
- The remaining 2-5% slack is reserved for unreachable defensive code paths
  (e.g. exhaustive `match` arms that PHPStan already proves complete).

PHPUnit is configured with `failOnRisky`, `failOnWarning`, and
`failOnDeprecation`, so any uncovered method that triggers a deprecation
or risky-test warning fails CI.

## Conformance test vectors

These are reproducible byte-for-byte tests of the RFCs. They live in
`tests/Conformance/Rfc/` with one class per RFC section.

### RFC 7515 (JWS)

- §A.1 — HS256 example (full computation, encoded form).
- §A.2 — RS256 example.
- §A.3 — ES256 example (Phase 2).
- §A.4 — ES512 example (Phase 2).
- §A.5 — Unsecured JWS (only the parser path; encoder is opt-in).

### RFC 7517 (JWK)

- §A.1 — RSA public key.
- §A.2 — RSA private key.
- §A.3 — Symmetric key.
- §B — X.509 certificate chain example (parse only).
- §C — JWK encryption (Phase 3).

### RFC 7519 (JWT)

- §3.1 — HS256 example.
- §6.1 — Unsecured JWT (parser path only).
- §A.1 — Encrypted JWT (Phase 3).
- §A.2 — Nested JWT (Phase 3).

### RFC 7520 (JOSE Cookbook)

The full cookbook becomes test fixtures, organised by section. Anything
in the cookbook that uses an algorithm we support must round-trip exactly.

### RFC 7797 (Phase 4)

- §4.1 — Standard JWS with HS256 (control case).
- §4.2 — `b64:false` with HS256 and a detached payload.
- §4.2 — Same with non-detached payload via JWS JSON Serialization.

### RFC 8725 — the PoCs themselves

These deserve their own subfolder, `tests/Conformance/Attacks/`:

- `AlgNoneBypassTest` — token with `alg:none`, library must reject.
- `Rs256ToHs256ConfusionTest` — McLean PoC, library must reject.
- `InvalidCurveAttackTest` — Sanso/Valenta vectors, library must throw
  `DecryptionException` (Phase 3).
- `DuplicateClaimNameTest` — RFC 7519 §4, library must reject.
- `JkuSsrfAttemptTest` — `jku` header pointing at attacker URL, library
  must not fetch.

Each attack test reads from a fixture file with the actual hostile token
or vector. The fixtures are committed; that way reviewers can verify
that the test really uses the published PoC bytes and not a sanitised
version.

## Unit testing conventions

```php
namespace Medzuch\Jwt\Tests\Unit\Jwt;

use Medzuch\Jwt\Jwt\JwtBuilder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(JwtBuilder::class)]
final class JwtBuilderTest extends TestCase
{
    public function testBuilderIsImmutable(): void { /* ... */ }

    #[DataProvider('invalidAudienceProvider')]
    public function testRejectsInvalidAudience(mixed $aud): void { /* ... */ }

    /** @return iterable<string, array{mixed}> */
    public static function invalidAudienceProvider(): iterable
    {
        yield 'empty string' => [''];
        yield 'integer' => [42];
        yield 'object' => [new \stdClass()];
    }
}
```

Conventions:

- One `#[CoversClass]` attribute per file. Anything not in `#[CoversClass]`
  is "incidentally covered", not "tested".
- `final` test classes, `final` test methods (they implicitly are, but
  the explicitness helps mutation testing).
- Data providers are `static` and return generators with named keys (so
  test output is readable).
- No PHPUnit annotations in docblocks; attributes only (PHPUnit 10+ style, required by PHPUnit 12).
- Test method names: `testItDoesX` or `testRejectsY`. No `it_*` snake_case.

## Mutation testing

Infection is configured at `infection.json5` with:

- `minMsi: 85` — overall mutation score must be ≥ 85%.
- `minCoveredMsi: 90` — score on covered code ≥ 90%.

CI runs mutation testing on `main` and on PRs labelled `run-mutation`. It
is too slow (~10 min) to run on every PR by default.

### When mutation testing matters most

Crypto-adjacent code. A mutant that flips a `>=` to `>` in a leeway check
must be killed by a test. A mutant that removes the `hash_equals` call
must be killed. These are exactly the bugs that ship.

## Property-based testing (planned, Phase 5)

For the parser and JSON layer, we'll add `eris/eris` or a homegrown
generator-based test that throws arbitrary byte strings at the parser
and asserts only specific exceptions can come out (no `Error`, no
`TypeError`, no panic).

## Fuzzing (planned, Phase 5)

`nikic/php-fuzzer` integrated as a nightly GitHub Actions job. Targets:

- `JwtParser::parse` — random compact strings.
- `Json::decode` — random byte sequences.
- `Base64Url::decode` — random ASCII.

Findings are auto-filed as issues with the input attached. Triage
priority: any crash that is not a `JwtException` subclass is P0.

## Local quick-check loop

While developing one component:

```bash
# Fastest feedback:
make sh
vendor/bin/phpunit --filter=ParserTest tests/Unit

# Before pushing:
composer qa
```

CI will run `qa:full` (adds coverage and mutation testing). The fast `qa`
target should not lie to you — if `qa` passes locally and `qa:full`
fails in CI, that's a bug in our setup.
