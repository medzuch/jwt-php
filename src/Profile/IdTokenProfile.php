<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use DateInterval;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyResolver;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Primitives\SystemClock;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;

/**
 * OpenID Connect Core 1.0 — ID Token profile (§2, §3.1.3.7).
 *
 * The producer side ({@see issuer()}) fills `iss` and `iat` and signs;
 * the caller supplies `sub`, the audience (the relying party's
 * `client_id`), and an expiry. The consumer side ({@see consumer()})
 * enforces the §2 required claims plus the ID-token-specific rules the
 * generic validator cannot express: an `azp` that must equal the client
 * when present (and must be present when the audience is plural), and an
 * optional `nonce` bound to the authentication request.
 *
 * No `typ` is enforced. OIDC Core does not mandate one and most identity
 * providers ship ID tokens without `id+jwt`; a deployment that wants
 * explicit typing can add it via {@see IdTokenBuilder::withHeader()} and
 * check it at the lower-level validator.
 */
final class IdTokenProfile
{
    /** OIDC Core §2 required ID Token claims. */
    private const REQUIRED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat'];

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
     * @param string|null                      $expectedNonce     if set, the token's `nonce` must equal it (OIDC §3.1.3.7)
     * @param ?DateInterval                    $leeway            clock-skew tolerance for `exp`/`nbf`/`iat` (RFC 7519 §4.1.4); null means none, and the bound is enforced by {@see ValidatorBuilder::withLeeway()}
     */
    public static function consumer(
        string $expectedIssuer,
        string $clientId,
        JwkSet|KeyResolver $keys,
        array $allowedAlgorithms,
        ?string $expectedNonce = null,
        ?ClockInterface $clock = null,
        ?LoggerInterface $logger = null,
        ?LogLevels $logLevels = null,
        ?DateInterval $leeway = null,
    ): IdTokenConsumer {
        $builder = ValidatorBuilder::create()
            ->expectAlgorithms($allowedAlgorithms)
            ->withKeys($keys)
            ->expectIssuer($expectedIssuer)
            ->expectAudience($clientId)
            ->requireClaims(self::REQUIRED_CLAIMS);

        if ($clock !== null) {
            $builder = $builder->withClock($clock);
        }
        if ($leeway !== null) {
            $builder = $builder->withLeeway($leeway);
        }

        return new IdTokenConsumer($builder->build(), $clientId, $expectedNonce, $logger, $logLevels);
    }

    /**
     * Fresh builder pre-seeded with `iss` and `iat` = now, signed with the
     * configured key (and its `kid`, when present). Auto claims are
     * last-write-wins and can be overridden on the builder.
     */
    public function issue(): IdTokenBuilder
    {
        $builder = JwtBuilder::create($this->clock)
            ->issuer($this->issuer)
            ->issuedAtNow()
            ->signWith($this->algorithm, $this->signingKey);

        // `PrivateKey` is a bare marker and `kid()` is declared on `Key`, so a
        // signing key from outside this library's hierarchy is legal here and
        // has no `kid()` to call — the `instanceof` is load-bearing, not
        // redundant. Such a key simply issues without a `kid` header.
        if ($this->signingKey instanceof Key && $this->signingKey->kid() !== null) {
            $builder = $builder->withHeader('kid', $this->signingKey->kid());
        }

        return new IdTokenBuilder($builder);
    }
}
