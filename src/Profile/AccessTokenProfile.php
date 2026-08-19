<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use DateInterval;
use LogicException;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Jwt\MediaType;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyResolver;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Primitives\Random;
use Medzuch\Jwt\Primitives\SystemClock;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;

/**
 * RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens.
 *
 * The producer side ({@see issuer()}) stamps `typ: at+jwt` (§2.1) and
 * guarantees the §2.2 required claims an access token cannot ship without
 * — `iss`, `iat`, and `jti` are filled automatically (the caller supplies
 * `sub`, `aud`, `client_id`, and an expiry). The consumer side
 * ({@see consumer()}) refuses any token that is not `at+jwt` and that does
 * not carry the full required-claim set, on top of signature, issuer, and
 * audience checks.
 *
 * An instance returned by {@see issuer()} is reusable: each {@see issue()}
 * call returns a fresh, independent builder, so one configured profile can
 * mint many tokens.
 */
final class AccessTokenProfile
{
    /**
     * Registered + RFC 9068 claims an access token MUST carry (§2.2).
     */
    private const REQUIRED_CLAIMS = ['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti'];

    private function __construct(
        private readonly string $issuer,
        private readonly SigningAlgorithm $algorithm,
        private readonly PrivateKey $signingKey,
        private readonly ClockInterface $clock,
    ) {}

    public static function issuer(
        string $issuer,
        SigningAlgorithm $algorithm,
        PrivateKey $signingKey,
        ?ClockInterface $clock = null,
    ): self {
        return new self($issuer, $algorithm, $signingKey, $clock ?? new SystemClock());
    }

    /**
     * @param string|non-empty-list<string>    $expectedAudience one or more
     *   identifiers this resource server answers to; a token is accepted when
     *   its `aud` names any of them (RFC 7519 §4.1.3 makes `aud` a set on both
     *   sides). An empty list is refused rather than treated as "no audience
     *   check" — see below.
     * @param non-empty-list<SigningAlgorithm> $allowedAlgorithms
     * @param ?DateInterval                    $leeway clock-skew tolerance for
     *   `exp`/`nbf`/`iat` (RFC 7519 §4.1.4). Null means none. The bound lives
     *   in {@see ValidatorBuilder::withLeeway()}, which rejects a negative
     *   interval and anything above
     *   {@see ValidatorBuilder::LEEWAY_CEILING_SECONDS} — a generous leeway
     *   silently widens the window in which an expired token is still
     *   accepted, so it is capped rather than trusted.
     */
    public static function consumer(
        string $expectedIssuer,
        string|array $expectedAudience,
        JwkSet|KeyResolver $keys,
        array $allowedAlgorithms,
        ?ClockInterface $clock = null,
        ?LoggerInterface $logger = null,
        ?LogLevels $logLevels = null,
        ?DateInterval $leeway = null,
    ): AccessTokenConsumer {
        // `ValidatorBuilder::expectAudience([])` reads as "no expected
        // audiences", which switches the check off entirely. On a profile that
        // advertises audience validation as one of its guarantees, silently
        // accepting every `aud` is the wrong reading of an empty list, so it is
        // a wiring error here. Runtime backstop: PHPStan's narrowing from the
        // docblock makes this "always false", but it fires for non-PHPStan
        // callers — a bundle mapping a YAML/JSON config key being the case
        // that matters (same idiom as JwtBuilder::assertAudienceShape()).
        // @phpstan-ignore identical.alwaysFalse
        if ($expectedAudience === []) {
            throw new LogicException('AccessTokenProfile::consumer() requires at least one expected audience; an empty list would disable the audience check');
        }

        $builder = ValidatorBuilder::create()
            ->expectAlgorithms($allowedAlgorithms)
            ->withKeys($keys)
            ->expectIssuer($expectedIssuer)
            ->expectAudience($expectedAudience)
            ->expectType(MediaType::accessToken())
            ->requireClaims(self::REQUIRED_CLAIMS);

        if ($clock !== null) {
            $builder = $builder->withClock($clock);
        }
        if ($leeway !== null) {
            $builder = $builder->withLeeway($leeway);
        }

        // The consumer is the logging owner for the profile path, so the
        // validator is built without a logger (see ProfileConsumer).
        return new AccessTokenConsumer($builder->build(), 'access-token', $logger, $logLevels);
    }

    /**
     * Fresh builder pre-seeded with the producer-side invariants: `at+jwt`
     * type, the configured issuer, `iat` = now, and a random `jti`. The
     * `kid` header is set from the signing key when it carries one. Auto
     * claims are last-write-wins, so {@see AccessTokenBuilder::issuedAt()}
     * and {@see AccessTokenBuilder::jwtId()} can override them.
     */
    public function issue(): AccessTokenBuilder
    {
        $builder = JwtBuilder::create($this->clock)
            ->type(MediaType::accessToken())
            ->issuer($this->issuer)
            ->issuedAtNow()
            ->jwtId(self::generateJti())
            ->signWith($this->algorithm, $this->signingKey);

        // `PrivateKey` is a bare marker and `kid()` is declared on `Key`, so a
        // signing key from outside this library's hierarchy is legal here and
        // has no `kid()` to call — the `instanceof` is load-bearing, not
        // redundant. Such a key simply issues without a `kid` header.
        if ($this->signingKey instanceof Key && $this->signingKey->kid() !== null) {
            $builder = $builder->withHeader('kid', $this->signingKey->kid());
        }

        return new AccessTokenBuilder($builder);
    }

    /**
     * 128 bits of randomness, hex-encoded — collision-resistant enough to
     * be a per-token identifier without coordination (RFC 9068 §4 leans on
     * `jti` for replay tracking).
     */
    private static function generateJti(): string
    {
        return bin2hex(Random::bytes(16));
    }
}
