<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt\Unsecured;

use DateInterval;
use DateTimeInterface;
use LogicException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\SystemClock;
use Psr\Clock\ClockInterface;

/**
 * Builds an `alg: none` compact JWT — header.payload. with an empty
 * signature segment.
 *
 * On its own namespace so a glob import of the regular `Jwt\*` cannot
 * reach it. The CompactSerializer used by the safe parsers refuses
 * empty-signature segments, so tokens produced here cannot round-trip
 * through {@see \Medzuch\Jwt\Jwt\JwtParser}. That is by design — this
 * builder exists for legacy interop and testing, not for any production
 * flow.
 */
final class UnsecuredJwtBuilder
{
    private const RESERVED_HEADERS = ['alg', 'b64'];

    private const REGISTERED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    private function __construct(
        private readonly array $claims,
        private readonly array $headers,
        private readonly ClockInterface $clock,
    ) {}

    public static function create(?ClockInterface $clock = null): self
    {
        return new self([], [], $clock ?? new SystemClock());
    }

    public function withClock(ClockInterface $clock): self
    {
        return new self($this->claims, $this->headers, $clock);
    }

    public function issuer(string $iss): self
    {
        return $this->withRegisteredClaim('iss', $iss);
    }

    public function subject(string $sub): self
    {
        return $this->withRegisteredClaim('sub', $sub);
    }

    /** @param string|list<string> $aud */
    public function audience(string|array $aud): self
    {
        return $this->withRegisteredClaim('aud', $aud);
    }

    public function expiresAt(DateTimeInterface $when): self
    {
        return $this->withRegisteredClaim('exp', $when->getTimestamp());
    }

    public function expiresIn(DateInterval $delta): self
    {
        return $this->expiresAt($this->clock->now()->add($delta));
    }

    public function notBefore(DateTimeInterface $when): self
    {
        return $this->withRegisteredClaim('nbf', $when->getTimestamp());
    }

    public function notBeforeNow(): self
    {
        return $this->notBefore($this->clock->now());
    }

    public function issuedAt(DateTimeInterface $when): self
    {
        return $this->withRegisteredClaim('iat', $when->getTimestamp());
    }

    public function issuedAtNow(): self
    {
        return $this->issuedAt($this->clock->now());
    }

    public function jwtId(string $jti): self
    {
        return $this->withRegisteredClaim('jti', $jti);
    }

    public function type(string $typ): self
    {
        $headers = $this->headers;
        $headers['typ'] = $typ;

        return new self($this->claims, $headers, $this->clock);
    }

    public function withClaim(string $name, mixed $value): self
    {
        if (in_array($name, self::REGISTERED_CLAIMS, true)) {
            throw new LogicException(sprintf('Use the dedicated %s() method for registered claim "%s"', $name, $name));
        }
        $claims = $this->claims;
        $claims[$name] = $value;

        return new self($claims, $this->headers, $this->clock);
    }

    public function withHeader(string $name, mixed $value): self
    {
        if (in_array($name, self::RESERVED_HEADERS, true)) {
            throw new InvalidHeaderException(sprintf('Header "%s" is reserved', $name));
        }
        $headers = $this->headers;
        $headers[$name] = $value;

        return new self($this->claims, $headers, $this->clock);
    }

    public function build(): CompactJws
    {
        $headers = $this->headers;
        $headers['alg'] = 'none';

        $payload = $this->claims === [] ? '{}' : Json::encode($this->claims);

        return CompactSerializer::serialize($headers, $payload, '');
    }

    private function withRegisteredClaim(string $name, mixed $value): self
    {
        $claims = $this->claims;
        $claims[$name] = $value;

        return new self($claims, $this->headers, $this->clock);
    }
}
