<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

use LogicException;
use Stringable;

/**
 * The `typ` header value declared on a JWT — its IANA-registered media
 * type (RFC 7519 §5.1, RFC 8725 §3.11).
 *
 * Explicit typing is one of the BCP 225 recommendations: every JWT used
 * in a specific application context should declare what *kind* of token
 * it is, so validators in another context cannot accidentally accept it.
 * This class is a typed wrapper around the `typ` header value, used by
 * {@see JwtBuilder::type()} on the producer side and by
 * {@see ValidatorBuilder::expectType()} on the consumer side.
 *
 * The shipped constants cover the three media types the library
 * recognises directly:
 *
 * - {@see jwt()} — `"JWT"`, the legacy generic value from RFC 7519 §5.1.
 * - {@see accessToken()} — `"at+jwt"` for OAuth 2.0 access tokens
 *   (RFC 9068).
 * - {@see idToken()} — `"id+jwt"` for OpenID Connect ID tokens
 *   (per draft-ietf-oauth-jwt-identity-token).
 * - {@see securityEventToken()} — `"secevent+jwt"` for Security Event
 *   Tokens (RFC 8417 §2.2).
 *
 * Application-specific media types use {@see custom()}; the rule of
 * thumb (RFC 7515 §4.1.9, BCP 225) is *"name+jwt"* without the
 * `application/` prefix.
 *
 * Two `MediaType` instances compare equal via `==` when their `$value`
 * matches; the {@see Validator}'s media-type matching also tolerates an
 * incoming `application/X+jwt` form against a stored `X+jwt` expectation,
 * matching RFC 7515 §4.1.9.
 */
final class MediaType implements Stringable
{
    /**
     * @param non-empty-string $value the bare `typ` header value (no `application/` prefix)
     */
    private function __construct(public readonly string $value) {}

    /**
     * Legacy `"JWT"` (RFC 7519 §5.1). Avoid in new contexts — prefer
     * a context-specific `application/X+jwt` value so validators can
     * reject tokens minted for another use.
     */
    public static function jwt(): self
    {
        return new self('JWT');
    }

    /**
     * `"at+jwt"` for OAuth 2.0 JWT-encoded access tokens (RFC 9068 §2.1).
     */
    public static function accessToken(): self
    {
        return new self('at+jwt');
    }

    /**
     * `"id+jwt"` for OpenID Connect ID tokens
     * (draft-ietf-oauth-jwt-identity-token).
     */
    public static function idToken(): self
    {
        return new self('id+jwt');
    }

    /**
     * `"secevent+jwt"` for Security Event Tokens (RFC 8417 §2.2).
     */
    public static function securityEventToken(): self
    {
        return new self('secevent+jwt');
    }

    /**
     * Application-defined media type. The value is required to be a
     * non-empty string; per RFC 6838 §4.2 the registered form is
     * `name+jwt` without the `application/` prefix, but this library
     * intentionally does not enforce the suffix so application-private
     * subtypes (e.g. `vendor.example.session+jwt`, or transitional
     * names with no `+jwt` suffix at all) remain expressible. Use the
     * shipped constants when one fits — they survive a typo audit.
     */
    public static function custom(string $value): self
    {
        if ($value === '') {
            throw new LogicException('MediaType value cannot be empty');
        }

        return new self($value);
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
