<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Primitives;

use Medzuch\Jwt\Exception\MalformedJwtException;
use SodiumException;

use function sodium_base642bin;
use function sodium_bin2base64;

use const SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING;

/**
 * Base64url encoding per RFC 7515 §2 (base64url with no padding).
 *
 * Backed by libsodium's `sodium_*base64*` family, which is implemented in
 * constant time. The standard `base64_encode`/`base64_decode` are not, and
 * we sign and verify byte strings whose contents must not leak through
 * encode/decode timing.
 */
final class Base64Url
{
    /** @codeCoverageIgnore */
    private function __construct()
    {
    }

    public static function encode(string $bytes): string
    {
        return sodium_bin2base64($bytes, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * @throws MalformedJwtException if the input contains characters outside
     *                               the base64url alphabet or has invalid length
     */
    public static function decode(string $encoded): string
    {
        try {
            return sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (SodiumException $e) {
            throw new MalformedJwtException('Input is not valid base64url', 0, $e);
        }
    }
}
