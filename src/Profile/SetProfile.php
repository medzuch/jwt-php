<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use DateInterval;
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
 * RFC 8417 — Security Event Token (SET) profile.
 *
 * The producer side ({@see issuer()}) stamps `typ: secevent+jwt` (§2.3),
 * fills `iss`/`iat`/`jti`, and signs; the caller adds the `events` object
 * and any subject/audience. The consumer side ({@see consumer()}) enforces
 * the §2.2 required claims and that `events` is a non-empty JSON object.
 *
 * The `secevent+jwt` type is only a SHOULD in RFC 8417, but this profile
 * sets it on the producer side and requires it on the consumer side — the
 * library's explicit-typing posture (RFC 8725 §3.11). A SET from an issuer
 * that omits `typ` must be validated through the lower-level API.
 *
 * Note that `exp` is deliberately not offered on the builder: RFC 8417
 * §4.1.4 says it is not meaningful for SETs (a security event is a
 * statement about something that happened, not a credential with a
 * lifetime).
 */
final class SetProfile
{
    /** RFC 8417 §2.2 required SET claims. */
    private const REQUIRED_CLAIMS = ['iss', 'iat', 'jti', 'events'];

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
     * @param string|null                      $expectedAudience  enforced when set (RFC 8417 §2.2 RECOMMENDS `aud`)
     * @param ?DateInterval                    $leeway            clock-skew tolerance for `exp`/`nbf`/`iat` (RFC 7519 §4.1.4); null means none, and the bound is enforced by {@see ValidatorBuilder::withLeeway()}
     */
    public static function consumer(
        string $expectedIssuer,
        JwkSet|KeyResolver $keys,
        array $allowedAlgorithms,
        ?string $expectedAudience = null,
        ?ClockInterface $clock = null,
        ?LoggerInterface $logger = null,
        ?LogLevels $logLevels = null,
        ?DateInterval $leeway = null,
    ): SetConsumer {
        $builder = ValidatorBuilder::create()
            ->expectAlgorithms($allowedAlgorithms)
            ->withKeys($keys)
            ->expectIssuer($expectedIssuer)
            ->expectType(MediaType::securityEventToken())
            ->requireClaims(self::REQUIRED_CLAIMS);

        if ($expectedAudience !== null) {
            $builder = $builder->expectAudience($expectedAudience);
        }
        if ($clock !== null) {
            $builder = $builder->withClock($clock);
        }
        if ($leeway !== null) {
            $builder = $builder->withLeeway($leeway);
        }

        return new SetConsumer($builder->build(), 'set', $logger, $logLevels);
    }

    /**
     * Fresh builder pre-seeded with `secevent+jwt`, the issuer, `iat` = now,
     * a random `jti`, and signing (with the key's `kid` when present).
     */
    public function issue(): SetBuilder
    {
        $builder = JwtBuilder::create($this->clock)
            ->type(MediaType::securityEventToken())
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

        return new SetBuilder($builder, []);
    }

    private static function generateJti(): string
    {
        return bin2hex(Random::bytes(16));
    }
}
