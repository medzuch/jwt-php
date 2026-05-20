<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key\Internal;

use function base64_encode;
use function chr;
use function chunk_split;
use function ltrim;
use function ord;
use function strlen;

/**
 * Minimal ASN.1 DER encoder for the structures we need to reconstruct
 * RSA PKCS#1 PEMs from JWK parameters.
 *
 * Only DER (definite-length, no indefinite) and only the tags we use:
 *   - INTEGER (0x02) — for RSA components
 *   - SEQUENCE (0x30) — for the wrapper types
 *
 * @internal used by RsaPublicKey/RsaPrivateKey to bridge JWK → PEM
 */
final class Asn1
{
    private const TAG_INTEGER = "\x02";
    private const TAG_SEQUENCE = "\x30";

    /** @codeCoverageIgnore */
    private function __construct()
    {
    }

    /**
     * Encode a positive integer (as raw big-endian bytes) as a DER INTEGER.
     *
     * Per X.690, INTEGER is two's complement: if the high bit of the first
     * byte is set, the value would be interpreted as negative — we prepend
     * a 0x00 padding byte to keep it positive. We also strip leading 0x00
     * bytes that would just be redundant padding.
     */
    public static function integer(string $bytes): string
    {
        // Strip redundant leading null bytes (but keep at least one byte).
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }

        // Prepend 0x00 if the high bit is set, to disambiguate from a
        // negative integer.
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return self::TAG_INTEGER . self::length(strlen($bytes)) . $bytes;
    }

    /**
     * Encode an arbitrary concatenation of DER values as a DER SEQUENCE.
     */
    public static function sequence(string $contents): string
    {
        return self::TAG_SEQUENCE . self::length(strlen($contents)) . $contents;
    }

    /**
     * Wrap a DER blob in a PEM envelope with the given label.
     *
     * @param non-empty-string $label e.g. "RSA PUBLIC KEY", "RSA PRIVATE KEY"
     */
    public static function toPem(string $der, string $label): string
    {
        $base64 = base64_encode($der);
        $wrapped = chunk_split($base64, 64, "\n");

        return "-----BEGIN {$label}-----\n{$wrapped}-----END {$label}-----\n";
    }

    /**
     * Encode a DER length field per X.690 §8.1.3.
     *
     * Short form for lengths < 128, long form otherwise.
     */
    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';
        $n = $length;
        while ($n > 0) {
            $bytes = chr($n & 0xFF) . $bytes;
            $n >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
