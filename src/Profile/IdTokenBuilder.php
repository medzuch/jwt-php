<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use DateInterval;
use DateTimeInterface;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jwt\JwtBuilder;

/**
 * Fluent, immutable builder for an OpenID Connect ID Token. Returned by
 * {@see IdTokenProfile::issue()} with `iss`/`iat` and signing applied; the
 * caller adds `sub`, the audience (the relying party's `client_id`), an
 * expiry, and any of the optional OIDC claims below.
 *
 * @internal construct via {@see IdTokenProfile::issue()}
 */
final class IdTokenBuilder
{
    public function __construct(private readonly JwtBuilder $builder) {}

    public function subject(string $sub): self
    {
        return new self($this->builder->subject($sub));
    }

    /**
     * The relying party the token is for. OIDC ID tokens carry the RP's
     * `client_id` in `aud` (OIDC Core §2).
     *
     * @param string|list<string> $aud
     */
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
     * String value used to associate a client session with the ID token and
     * mitigate replay (OIDC Core §2). Echoed from the authentication request.
     */
    public function nonce(string $nonce): self
    {
        return new self($this->builder->withClaim('nonce', $nonce));
    }

    /**
     * Authorized party (`azp`) — the `client_id` of the party the token was
     * issued to. Required when the audience is plural or contains a value
     * that is not the client (OIDC Core §2).
     */
    public function authorizedParty(string $clientId): self
    {
        return new self($this->builder->withClaim('azp', $clientId));
    }

    /**
     * Time of the end-user authentication (`auth_time`, OIDC Core §2), as a
     * NumericDate.
     */
    public function authTime(DateTimeInterface $when): self
    {
        return new self($this->builder->withClaim('auth_time', $when->getTimestamp()));
    }

    /**
     * Authentication Context Class Reference (`acr`, OIDC Core §2).
     */
    public function acr(string $acr): self
    {
        return new self($this->builder->withClaim('acr', $acr));
    }

    /**
     * Authentication Methods References (`amr`, OIDC Core §2).
     *
     * @param list<string> $methods
     */
    public function amr(array $methods): self
    {
        return new self($this->builder->withClaim('amr', $methods));
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
