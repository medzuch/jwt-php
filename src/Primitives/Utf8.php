<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Primitives;

use Medzuch\Jwt\Exception\MalformedJwtException;

/**
 * UTF-8 well-formedness validation.
 *
 * Mitigates T7 (multi-encoding JSON ambiguity, RFC 8725 §3.7): the parser
 * must only accept UTF-8, and must reject byte-order marks because they can
 * make a downstream JSON parser fall back to a different encoding.
 */
final class Utf8
{
    private const UTF8_BOM = "\xEF\xBB\xBF";
    private const UTF16_BE_BOM = "\xFE\xFF";
    private const UTF16_LE_BOM = "\xFF\xFE";

    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * True iff $bytes is a well-formed UTF-8 sequence with no BOM.
     *
     * PHP's mbstring (built against modern Unicode) rejects overlong
     * sequences and unpaired surrogates as ill-formed, satisfying RFC 3629.
     */
    public static function isValid(string $bytes): bool
    {
        if (self::startsWithBom($bytes)) {
            return false;
        }

        return mb_check_encoding($bytes, 'UTF-8');
    }

    /**
     * @throws MalformedJwtException
     */
    public static function assertValid(string $bytes): void
    {
        if (!self::isValid($bytes)) {
            throw new MalformedJwtException('Input is not well-formed UTF-8 (RFC 8725 §3.7)');
        }
    }

    private static function startsWithBom(string $bytes): bool
    {
        return str_starts_with($bytes, self::UTF8_BOM)
            || str_starts_with($bytes, self::UTF16_BE_BOM)
            || str_starts_with($bytes, self::UTF16_LE_BOM);
    }
}
