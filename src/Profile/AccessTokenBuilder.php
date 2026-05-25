<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use DateInterval;
use DateTimeInterface;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jwt\JwtBuilder;

/**
 * Fluent, immutable builder for an RFC 9068 access token. Returned by
 * {@see AccessTokenProfile::issue()} with the producer-side invariants
 * already applied; the caller fills in the request-specific claims.
 *
 * Each method returns a new builder. The profile's required claims that
 * are not auto-filled — `sub`, `aud`, `client_id`, and an expiry — are the
 * caller's responsibility; omitting them produces a token the matching
 * {@see AccessTokenConsumer} will reject.
 *
 * @internal construct via {@see AccessTokenProfile::issue()}
 */
final class AccessTokenBuilder
{
    public function __construct(private readonly JwtBuilder $builder) {}

    public function subject(string $sub): self
    {
        return new self($this->builder->subject($sub));
    }

    /** @param string|list<string> $aud */
    public function audience(string|array $aud): self
    {
        return new self($this->builder->audience($aud));
    }

    public function expiresAt(DateTimeInterface $when): self
    {
        return new self($this->builder->expiresAt($when));
    }

    public function expiresIn(DateInterval $delta): self
    {
        return new self($this->builder->expiresIn($delta));
    }

    public function notBefore(DateTimeInterface $when): self
    {
        return new self($this->builder->notBefore($when));
    }

    public function issuedAt(DateTimeInterface $when): self
    {
        return new self($this->builder->issuedAt($when));
    }

    public function jwtId(string $jti): self
    {
        return new self($this->builder->jwtId($jti));
    }

    /**
     * The OAuth 2.0 client the token was issued to (RFC 9068 §2.2,
     * `client_id` from RFC 8693). Required by the profile.
     */
    public function clientId(string $clientId): self
    {
        return new self($this->builder->withClaim('client_id', $clientId));
    }

    /**
     * OAuth 2.0 scopes. Serialised as the space-delimited `scope` string
     * (RFC 9068 §2.2.3, RFC 6749 §3.3), not a JSON array.
     *
     * @param list<string> $scopes
     */
    public function scope(array $scopes): self
    {
        return new self($this->builder->withClaim('scope', implode(' ', $scopes)));
    }

    /**
     * Time of the end-user authentication that produced this token
     * (`auth_time`, RFC 9068 §2.2.1), as a NumericDate.
     */
    public function authTime(DateTimeInterface $when): self
    {
        return new self($this->builder->withClaim('auth_time', $when->getTimestamp()));
    }

    public function withClaim(string $name, mixed $value): self
    {
        return new self($this->builder->withClaim($name, $value));
    }

    public function withHeader(string $name, mixed $value): self
    {
        return new self($this->builder->withHeader($name, $value));
    }

    public function build(): CompactJws
    {
        return $this->builder->build();
    }
}
