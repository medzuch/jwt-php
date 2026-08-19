<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

use DateInterval;
use DateTimeImmutable;
use LogicException;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\KeyResolver;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\SystemClock;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;

/**
 * Builds an immutable {@see Validator}. All `with*` / `expect*` calls return
 * a new builder. {@see build()} fails closed if the mandatory pieces — at
 * least one algorithm + a key source — are missing.
 */
final class ValidatorBuilder
{
    /**
     * Hard ceiling on clock-skew leeway. RFC 7519 §4.1.4 deliberately does
     * not name a number; we pick 5 minutes as a defensible upper bound and
     * refuse anything larger. A token that needs more leeway than that is
     * almost always a sign of an issuer/consumer clock that needs fixing,
     * not a leeway problem.
     */
    public const LEEWAY_CEILING_SECONDS = 300;

    /**
     * @param list<SigningAlgorithm> $allowedAlgorithms
     * @param list<string>           $expectedIssuers
     * @param list<string>           $expectedAudiences
     * @param list<string>           $requiredClaims
     */
    private function __construct(
        private readonly array $allowedAlgorithms,
        private readonly ?KeyResolver $keyResolver,
        private readonly ClockInterface $clock,
        private readonly DateInterval $leeway,
        private readonly array $expectedIssuers,
        private readonly array $expectedAudiences,
        private readonly ?string $expectedSubject,
        private readonly ?string $expectedType,
        private readonly array $requiredClaims,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?LogLevels $logLevels = null,
    ) {}

    public static function create(): self
    {
        return new self(
            allowedAlgorithms: [],
            keyResolver: null,
            clock: new SystemClock(),
            leeway: new DateInterval('PT0S'),
            expectedIssuers: [],
            expectedAudiences: [],
            expectedSubject: null,
            expectedType: null,
            requiredClaims: [],
        );
    }

    /** @param non-empty-list<SigningAlgorithm> $algorithms */
    public function expectAlgorithms(array $algorithms): self
    {
        return $this->copyWith(allowedAlgorithms: $algorithms);
    }

    public function withKeys(JwkSet|KeyResolver $keys): self
    {
        $resolver = $keys instanceof KeyResolver ? $keys : new StaticJwkSetResolver($keys);

        return $this->copyWith(keyResolver: $resolver);
    }

    public function withClock(ClockInterface $clock): self
    {
        return $this->copyWith(clock: $clock);
    }

    public function withLeeway(DateInterval $leeway): self
    {
        $seconds = self::secondsIn($leeway);
        if ($seconds < 0) {
            throw new LogicException('Leeway must be non-negative');
        }
        if ($seconds > self::LEEWAY_CEILING_SECONDS) {
            throw new LogicException(sprintf('Leeway %ds exceeds the hard ceiling of %ds (RFC 7519 §4.1.4)', $seconds, self::LEEWAY_CEILING_SECONDS));
        }

        return $this->copyWith(leeway: $leeway);
    }

    /** @param string|list<string> $iss any-of */
    public function expectIssuer(string|array $iss): self
    {
        return $this->copyWith(expectedIssuers: self::asExpectedSet('expectIssuer', $iss));
    }

    /** @param string|list<string> $aud any-of */
    public function expectAudience(string|array $aud): self
    {
        return $this->copyWith(expectedAudiences: self::asExpectedSet('expectAudience', $aud));
    }

    public function expectSubject(string $sub): self
    {
        return $this->copyWith(expectedSubject: $sub);
    }

    public function expectType(MediaType|string $typ): self
    {
        return $this->copyWith(expectedType: $typ instanceof MediaType ? $typ->value : $typ);
    }

    /** @param list<string> $names */
    public function requireClaims(array $names): self
    {
        return $this->copyWith(requiredClaims: $names);
    }

    /**
     * Attach an optional PSR-3 logger. The built {@see Validator} emits a
     * redacted diagnostic event per outcome (accepted / signature failure /
     * claim rejection) — never tokens, payloads, claim values, or key
     * material. Pass {@see LogLevels} to remap which level each event is
     * emitted at; omit it for the secure defaults.
     */
    public function withLogger(LoggerInterface $logger, ?LogLevels $levels = null): self
    {
        // Set directly rather than via copyWith() so $levels can be left null
        // (meaning "use the defaults") without copyWith's coalesce reviving a
        // previously set map.
        return new self(
            $this->allowedAlgorithms,
            $this->keyResolver,
            $this->clock,
            $this->leeway,
            $this->expectedIssuers,
            $this->expectedAudiences,
            $this->expectedSubject,
            $this->expectedType,
            $this->requiredClaims,
            $logger,
            $levels,
        );
    }

    public function build(): Validator
    {
        if ($this->allowedAlgorithms === []) {
            throw new LogicException('ValidatorBuilder requires at least one algorithm via expectAlgorithms()');
        }
        if ($this->keyResolver === null) {
            throw new LogicException('ValidatorBuilder requires a key source via withKeys()');
        }

        return new Validator(
            $this->allowedAlgorithms,
            $this->keyResolver,
            $this->clock,
            $this->leeway,
            $this->expectedIssuers,
            $this->expectedAudiences,
            $this->expectedSubject,
            $this->expectedType,
            $this->requiredClaims,
            $this->logger,
            $this->logLevels,
        );
    }

    /**
     * @param list<SigningAlgorithm>|null $allowedAlgorithms
     * @param list<string>|null           $expectedIssuers
     * @param list<string>|null           $expectedAudiences
     * @param list<string>|null           $requiredClaims
     */
    private function copyWith(
        ?array $allowedAlgorithms = null,
        ?KeyResolver $keyResolver = null,
        ?ClockInterface $clock = null,
        ?DateInterval $leeway = null,
        ?array $expectedIssuers = null,
        ?array $expectedAudiences = null,
        ?string $expectedSubject = null,
        ?string $expectedType = null,
        ?array $requiredClaims = null,
    ): self {
        return new self(
            $allowedAlgorithms ?? $this->allowedAlgorithms,
            $keyResolver ?? $this->keyResolver,
            $clock ?? $this->clock,
            $leeway ?? $this->leeway,
            $expectedIssuers ?? $this->expectedIssuers,
            $expectedAudiences ?? $this->expectedAudiences,
            $expectedSubject ?? $this->expectedSubject,
            $expectedType ?? $this->expectedType,
            $requiredClaims ?? $this->requiredClaims,
            $this->logger,
            $this->logLevels,
        );
    }

    /**
     * Normalise an any-of expectation to a list of strings, refusing shapes
     * the comparison could never match.
     *
     * {@see Validator} compares with `in_array(…, true)`, so a non-string
     * entry silently matches nothing and every token is rejected — once per
     * token, at parse time, phrased as a problem with the token. It is in
     * fact a wiring problem, and it was knowable here. An associative array
     * is the odd one out: `in_array()` ignores keys, so it happens to work
     * today. It is refused anyway, because "happens to work" is not the
     * contract, and the documented shape has always been `list<string>`.
     *
     * Mirrors {@see JwtBuilder::assertAudienceShape()} on the producer side.
     * Both are runtime backstops for callers who bypass static analysis —
     * a bundle mapping a YAML/JSON config key being the case that matters.
     * PHPStan narrows these away from the docblock, hence the ignores.
     *
     * @param string|list<string> $expected
     *
     * @return list<string>
     */
    private static function asExpectedSet(string $method, string|array $expected): array
    {
        if (is_string($expected)) {
            return [$expected];
        }
        // @phpstan-ignore function.alreadyNarrowedType
        if (!array_is_list($expected)) {
            throw new LogicException(sprintf('%s() requires a string or a list of strings; got an associative array', $method));
        }
        foreach ($expected as $entry) {
            // @phpstan-ignore function.alreadyNarrowedType
            if (!is_string($entry)) {
                throw new LogicException(sprintf('%s() list entries must all be strings', $method));
            }
        }

        return $expected;
    }

    private static function secondsIn(DateInterval $interval): int
    {
        $epoch = new DateTimeImmutable('@0');

        return $epoch->add($interval)->getTimestamp();
    }
}
