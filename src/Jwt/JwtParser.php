<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Primitives\Json;

/**
 * Phase-1 parser. Returns a structurally valid {@see ParsedJwt} or throws.
 * No crypto, no claim validation — those happen in {@see Validator}.
 */
final class JwtParser
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    public static function parse(string $compact): ParsedJwt
    {
        $jws = CompactSerializer::deserialize($compact);

        // RFC 7797 §7 forbids `b64` in JWT headers. The JWS Verifier
        // (PR #4) refuses it too, but enforcing it here means a caller
        // who only structurally parses still sees the refusal.
        if (array_key_exists('b64', $jws->header)) {
            throw new InvalidHeaderException('JWT header must not declare "b64" (RFC 7797 §7)');
        }

        $claims = Json::decode($jws->payload);

        return new ParsedJwt(
            new Header($jws->header),
            new ClaimsSet($claims),
            $jws,
        );
    }
}
