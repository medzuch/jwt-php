<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\ExpiredException;
use Medzuch\Jwt\Exception\InvalidAudienceException;
use Medzuch\Jwt\Exception\InvalidIssuerException;
use Medzuch\Jwt\Exception\InvalidSubjectException;
use Medzuch\Jwt\Exception\InvalidTypeException;
use Medzuch\Jwt\Exception\IssuedInFutureException;
use Medzuch\Jwt\Exception\MissingClaimException;
use Medzuch\Jwt\Exception\NotYetValidException;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\KeyResolver;
use Psr\Clock\ClockInterface;

/**
 * Phase-2 validator. Run a {@see ParsedJwt} through:
 *   1. JWS signature verification (delegates to {@see Verifier}).
 *   2. Required-claim presence checks.
 *   3. Time-based checks (`exp`, `nbf`, `iat`) under a bounded leeway.
 *   4. Identity checks (`iss`, `sub`, `aud`).
 *   5. Type check on the `typ` header (RFC 8725 §3.11).
 *
 * Returned `ClaimsSet` is the validated claims; the caller is free to read.
 *
 * @see ValidatorBuilder to construct one.
 */
final class Validator
{
    /**
     * @param non-empty-list<SigningAlgorithm> $allowedAlgorithms
     * @param list<string>                     $expectedIssuers   any-of; empty = don't check
     * @param list<string>                     $expectedAudiences any-of; empty = don't check
     * @param list<string>                     $requiredClaims
     */
    public function __construct(
        private readonly array $allowedAlgorithms,
        private readonly KeyResolver $keyResolver,
        private readonly ClockInterface $clock,
        private readonly DateInterval $leeway,
        private readonly array $expectedIssuers,
        private readonly array $expectedAudiences,
        private readonly ?string $expectedSubject,
        private readonly ?string $expectedType,
        private readonly array $requiredClaims,
    ) {}

    public function validate(ParsedJwt $jwt): ClaimsSet
    {
        (new Verifier())->verify($jwt->jws, $this->allowedAlgorithms, $this->keyResolver);

        $claims = $jwt->unverifiedClaims;

        $this->assertType($jwt->header);
        $this->assertRequiredClaims($claims);
        $this->assertTimeBounds($claims);
        $this->assertIssuer($claims);
        $this->assertAudience($claims);
        $this->assertSubject($claims);

        return $claims;
    }

    private function assertType(Header $header): void
    {
        if ($this->expectedType === null) {
            return;
        }
        $typ = $header->type();
        if ($typ === null) {
            throw new InvalidTypeException(sprintf('Header "typ" is required and must equal "%s"', $this->expectedType));
        }
        if (!self::mediaTypeMatches($typ, $this->expectedType)) {
            throw new InvalidTypeException(sprintf('Header "typ" is "%s", expected "%s"', $typ, $this->expectedType));
        }
    }

    private function assertRequiredClaims(ClaimsSet $claims): void
    {
        foreach ($this->requiredClaims as $name) {
            if (!$claims->has($name)) {
                throw new MissingClaimException(sprintf('Required claim "%s" is missing', $name));
            }
        }
    }

    private function assertTimeBounds(ClaimsSet $claims): void
    {
        $now = $this->clock->now();
        $leewaySeconds = self::secondsIn($this->leeway);

        $exp = $claims->expiresAt();
        if ($exp !== null && $now->getTimestamp() - $leewaySeconds >= $exp->getTimestamp()) {
            throw new ExpiredException(sprintf('Token expired at %s (now %s)', $exp->format(DATE_ATOM), $now->format(DATE_ATOM)));
        }

        $nbf = $claims->notBefore();
        if ($nbf !== null && $now->getTimestamp() + $leewaySeconds < $nbf->getTimestamp()) {
            throw new NotYetValidException(sprintf('Token is not valid before %s (now %s)', $nbf->format(DATE_ATOM), $now->format(DATE_ATOM)));
        }

        $iat = $claims->issuedAt();
        if ($iat !== null && $iat->getTimestamp() - $leewaySeconds > $now->getTimestamp()) {
            throw new IssuedInFutureException(sprintf('Token claims to be issued at %s (now %s)', $iat->format(DATE_ATOM), $now->format(DATE_ATOM)));
        }
    }

    private function assertIssuer(ClaimsSet $claims): void
    {
        if ($this->expectedIssuers === []) {
            return;
        }
        $iss = $claims->issuer();
        if ($iss === null) {
            throw new InvalidIssuerException('Token has no "iss" claim');
        }
        if (!in_array($iss, $this->expectedIssuers, true)) {
            throw new InvalidIssuerException(sprintf('Token "iss" is "%s"; not in expected set', $iss));
        }
    }

    private function assertAudience(ClaimsSet $claims): void
    {
        if ($this->expectedAudiences === []) {
            return;
        }
        $aud = $claims->audience();
        if ($aud === []) {
            throw new InvalidAudienceException('Token has no "aud" claim');
        }
        foreach ($aud as $candidate) {
            if (in_array($candidate, $this->expectedAudiences, true)) {
                return;
            }
        }

        throw new InvalidAudienceException(sprintf('Token "aud" [%s] does not intersect expected set', implode(', ', $aud)));
    }

    private function assertSubject(ClaimsSet $claims): void
    {
        if ($this->expectedSubject === null) {
            return;
        }
        $sub = $claims->subject();
        if ($sub !== $this->expectedSubject) {
            throw new InvalidSubjectException(sprintf('Token "sub" is "%s", expected "%s"', $sub ?? '(null)', $this->expectedSubject));
        }
    }

    /**
     * `application/<type>+jwt` matches `<type>+jwt` (RFC 7515 §4.1.9):
     * media-type names can omit the `application/` prefix when unique.
     */
    private static function mediaTypeMatches(string $actual, string $expected): bool
    {
        if (strcasecmp($actual, $expected) === 0) {
            return true;
        }

        $normalise = static fn(string $t): string
            => str_starts_with(strtolower($t), 'application/')
                ? substr($t, strlen('application/'))
                : strtolower($t);

        return $normalise($actual) === $normalise($expected);
    }

    private static function secondsIn(DateInterval $interval): int
    {
        // PSR-20 instants are always anchored at UTC epoch; use them
        // to convert a DateInterval to absolute seconds.
        $epoch = new DateTimeImmutable('@0');

        return $epoch->add($interval)->getTimestamp();
    }
}
