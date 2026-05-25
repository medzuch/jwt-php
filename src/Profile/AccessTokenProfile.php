<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use Medzuch\Jwt\Algorithm\SigningAlgorithm;
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
     * @param non-empty-list<SigningAlgorithm> $allowedAlgorithms
     */
    public static function consumer(
        string $expectedIssuer,
        string $expectedAudience,
        JwkSet|KeyResolver $keys,
        array $allowedAlgorithms,
        ?ClockInterface $clock = null,
    ): AccessTokenConsumer {
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

        return new AccessTokenConsumer($builder->build());
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
