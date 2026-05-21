<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use LogicException;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\SystemClock;
use Psr\Clock\ClockInterface;

/**
 * Immutable fluent builder for compact JWTs. Each `with*` returns a new
 * builder; `build()` produces a signed {@see CompactJws}.
 */
final class JwtBuilder
{
    /**
     * Reserved header parameters the builder sets itself. Callers cannot
     * smuggle them in via {@see withHeader()} — `alg` because the Signer
     * fills it from the algorithm, `b64` because RFC 7797 §7 forbids it
     * in JWTs (T14).
     */
    private const RESERVED_HEADERS = ['alg', 'b64'];

    /**
     * Registered claims that have dedicated builder methods. Routed through
     * those methods rather than `withClaim` so the shape is enforced once.
     */
    private const REGISTERED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

    /**
     * @param array<string, mixed>                 $claims
     * @param array<string, mixed>                 $headers
     * @param array{0: SigningAlgorithm, 1: PrivateKey}|null $signing
     */
    private function __construct(
        private readonly array $claims,
        private readonly array $headers,
        private readonly ?array $signing,
        private readonly ClockInterface $clock,
    ) {}

    public static function create(?ClockInterface $clock = null): self
    {
        return new self([], [], null, $clock ?? new SystemClock());
    }

    public function withClock(ClockInterface $clock): self
    {
        return new self($this->claims, $this->headers, $this->signing, $clock);
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
        return $this->expiresAt($this->now()->add($delta));
    }

    public function notBefore(DateTimeInterface $when): self
    {
        return $this->withRegisteredClaim('nbf', $when->getTimestamp());
    }

    public function notBeforeNow(): self
    {
        return $this->notBefore($this->now());
    }

    public function issuedAt(DateTimeInterface $when): self
    {
        return $this->withRegisteredClaim('iat', $when->getTimestamp());
    }

    public function issuedAtNow(): self
    {
        return $this->issuedAt($this->now());
    }

    public function jwtId(string $jti): self
    {
        return $this->withRegisteredClaim('jti', $jti);
    }

    public function type(string $typ): self
    {
        $headers = $this->headers;
        $headers['typ'] = $typ;

        return new self($this->claims, $headers, $this->signing, $this->clock);
    }

    public function withClaim(string $name, mixed $value): self
    {
        if (in_array($name, self::REGISTERED_CLAIMS, true)) {
            // Force callers through the typed setters so the shape is
            // checked there, not deep inside Json::encode.
            throw new LogicException(sprintf('Use the dedicated %s() method for registered claim "%s"', $name, $name));
        }
        $claims = $this->claims;
        $claims[$name] = $value;

        return new self($claims, $this->headers, $this->signing, $this->clock);
    }

    public function withHeader(string $name, mixed $value): self
    {
        if (in_array($name, self::RESERVED_HEADERS, true)) {
            throw new InvalidHeaderException(sprintf('Header "%s" is reserved and cannot be set via withHeader()', $name));
        }
        $headers = $this->headers;
        $headers[$name] = $value;

        return new self($this->claims, $headers, $this->signing, $this->clock);
    }

    public function signWith(SigningAlgorithm $algorithm, PrivateKey $key): self
    {
        return new self($this->claims, $this->headers, [$algorithm, $key], $this->clock);
    }

    public function build(): CompactJws
    {
        if ($this->signing === null) {
            throw new LogicException('JwtBuilder::build() requires signWith() to be called first');
        }
        [$algorithm, $key] = $this->signing;

        // Empty PHP arrays serialise as `[]`; the JWT Claims Set MUST be a
        // JSON object (RFC 7519 §3.1), so emit `{}` explicitly.
        $payload = $this->claims === [] ? '{}' : Json::encode($this->claims);

        return (new Signer())->sign($algorithm, $this->headers, $payload, $key);
    }

    private function withRegisteredClaim(string $name, mixed $value): self
    {
        $claims = $this->claims;
        $claims[$name] = $value;

        return new self($claims, $this->headers, $this->signing, $this->clock);
    }

    private function now(): DateTimeImmutable
    {
        return $this->clock->now();
    }
}
