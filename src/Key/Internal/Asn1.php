<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key\Internal;

use Medzuch\Jwt\Exception\InvalidKeyException;

/**
 * Minimal ASN.1 DER encoder/decoder for the structures we need.
 *
 * Encoding side: enough to reconstruct PKCS#1 RSAPrivateKey PEMs and
 * RFC 5480 SubjectPublicKeyInfo / RFC 5915 ECPrivateKey PEMs from JWK
 * parameters. Decoding side: enough to convert ECDSA DER signatures
 * (SEQUENCE OF two INTEGERs) to the raw r||s form JOSE requires.
 *
 * Only DER (definite-length, no indefinite) and only the tags we use.
 *
 * @internal used by RSA/EC key classes and the ECDSA algorithm
 */
final class Asn1
{
    private const TAG_INTEGER = "\x02";
    private const TAG_BIT_STRING = "\x03";
    private const TAG_OCTET_STRING = "\x04";
    private const TAG_OID = "\x06";
    private const TAG_SEQUENCE = "\x30";

    // X.690 §8.1.2 identifier-octet bits.
    private const CLASS_CONTEXT_SPECIFIC = 0x80;
    private const CONSTRUCTED = 0x20;

    /** @codeCoverageIgnore */
    private function __construct() {}

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
     * Encode raw bytes as a DER OCTET STRING.
     */
    public static function octetString(string $bytes): string
    {
        return self::TAG_OCTET_STRING . self::length(strlen($bytes)) . $bytes;
    }

    /**
     * Encode raw bytes as a DER BIT STRING with zero unused trailing bits.
     *
     * The BIT STRING contents are `00 || bytes`; the leading `00` byte
     * declares that no bits in the final octet are unused, which is the
     * only case we need (whole-byte payloads like EC points).
     */
    public static function bitString(string $bytes): string
    {
        $contents = "\x00" . $bytes;

        return self::TAG_BIT_STRING . self::length(strlen($contents)) . $contents;
    }

    /**
     * Encode a dotted-decimal OID to DER (X.690 §8.19).
     *
     * The first two arcs combine into a single byte as `40 * arc1 + arc2`;
     * subsequent arcs are base-128 with continuation bits on every byte
     * except the last.
     *
     * @param non-empty-string $dotted e.g. "1.2.840.10045.2.1"
     */
    public static function oid(string $dotted): string
    {
        $arcs = explode('.', $dotted);
        if (count($arcs) < 2) {
            throw new InvalidKeyException(sprintf('OID must have at least two arcs, got "%s"', $dotted));
        }

        $arcInts = [];
        foreach ($arcs as $arc) {
            if ($arc === '' || !ctype_digit($arc)) {
                throw new InvalidKeyException(sprintf('OID arc "%s" is not a non-negative integer', $arc));
            }
            $arcInts[] = (int) $arc;
        }

        $first = $arcInts[0];
        $second = $arcInts[1];
        if ($first > 2 || ($first < 2 && $second > 39)) {
            throw new InvalidKeyException(sprintf('OID first/second arc out of range in "%s"', $dotted));
        }

        $body = chr(40 * $first + $second);
        for ($i = 2, $n = count($arcInts); $i < $n; $i++) {
            $body .= self::base128($arcInts[$i]);
        }

        return self::TAG_OID . self::length(strlen($body)) . $body;
    }

    /**
     * Wrap contents in an EXPLICIT context-specific tag [n].
     *
     * Used inside ECPrivateKey (RFC 5915) for the `[0] parameters` and
     * `[1] publicKey` optional fields.
     */
    public static function contextTagged(int $tag, string $contents): string
    {
        if ($tag < 0 || $tag > 30) {
            throw new InvalidKeyException(sprintf('Context tag %d out of supported range [0,30]', $tag));
        }
        // Constructed bit because the payload is itself DER-encoded.
        $tagByte = chr(self::CLASS_CONTEXT_SPECIFIC | self::CONSTRUCTED | $tag);

        return $tagByte . self::length(strlen($contents)) . $contents;
    }

    /**
     * Wrap a DER blob in a PEM envelope with the given label.
     *
     * @param non-empty-string $label e.g. "RSA PUBLIC KEY", "PUBLIC KEY", "EC PRIVATE KEY"
     */
    public static function toPem(string $der, string $label): string
    {
        $base64 = base64_encode($der);
        $wrapped = chunk_split($base64, 64, "\n");

        return "-----BEGIN {$label}-----\n{$wrapped}-----END {$label}-----\n";
    }

    /**
     * Decode an ECDSA DER signature `SEQUENCE { INTEGER r, INTEGER s }`
     * into the JOSE concatenation `r || s`, each component left-padded
     * with `\x00` to exactly `$coordSize` bytes.
     *
     * @param positive-int $coordSize
     *
     * @return non-empty-string exactly `2 * $coordSize` bytes
     *
     * @throws InvalidKeyException on malformed DER or oversized components
     */
    public static function ecdsaDerToRaw(string $der, int $coordSize): string
    {
        $offset = 0;
        $body = self::expectTagBody($der, $offset, self::TAG_SEQUENCE);
        if ($offset !== strlen($der)) {
            throw new InvalidKeyException('Trailing bytes after ECDSA DER SEQUENCE');
        }

        $inner = 0;
        $r = self::expectInteger($body, $inner);
        $s = self::expectInteger($body, $inner);
        if ($inner !== strlen($body)) {
            throw new InvalidKeyException('Trailing bytes inside ECDSA DER SEQUENCE');
        }

        return self::leftPad($r, $coordSize) . self::leftPad($s, $coordSize);
    }

    /**
     * Encode the JOSE concatenation `r || s` (each `$coordSize` bytes)
     * as an ECDSA DER signature `SEQUENCE { INTEGER r, INTEGER s }`.
     *
     * @param positive-int $coordSize
     *
     * @throws InvalidKeyException if the input length does not match `2*$coordSize`
     */
    public static function ecdsaRawToDer(string $raw, int $coordSize): string
    {
        if (strlen($raw) !== 2 * $coordSize) {
            throw new InvalidKeyException(sprintf('ECDSA raw signature must be %d bytes, got %d', 2 * $coordSize, strlen($raw)));
        }

        $r = substr($raw, 0, $coordSize);
        $s = substr($raw, $coordSize);

        return self::sequence(self::integer($r) . self::integer($s));
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

    /**
     * Encode a non-negative integer as base-128 with continuation bits.
     * Used inside OID arc 3+.
     */
    private static function base128(int $value): string
    {
        if ($value === 0) {
            return "\x00";
        }
        $out = chr($value & 0x7F);
        $value >>= 7;
        while ($value > 0) {
            $out = chr(0x80 | ($value & 0x7F)) . $out;
            $value >>= 7;
        }

        return $out;
    }

    /**
     * @param string $tag exactly one byte
     *
     * @throws InvalidKeyException
     */
    private static function expectTagBody(string $der, int &$offset, string $tag): string
    {
        if (!isset($der[$offset])) {
            throw new InvalidKeyException('ASN.1: unexpected end of input (expected tag)');
        }
        if ($der[$offset] !== $tag) {
            throw new InvalidKeyException(sprintf('ASN.1: expected tag 0x%02X at offset %d, got 0x%02X', ord($tag), $offset, ord($der[$offset])));
        }
        $offset++;
        $length = self::readLength($der, $offset);
        if ($offset + $length > strlen($der)) {
            throw new InvalidKeyException('ASN.1: declared length exceeds buffer');
        }
        $body = substr($der, $offset, $length);
        $offset += $length;

        return $body;
    }

    /**
     * @throws InvalidKeyException
     */
    private static function expectInteger(string $body, int &$offset): string
    {
        $bytes = self::expectTagBody($body, $offset, self::TAG_INTEGER);
        if ($bytes === '') {
            throw new InvalidKeyException('ASN.1: INTEGER body is empty');
        }
        if ((ord($bytes[0]) & 0x80) !== 0) {
            throw new InvalidKeyException('ASN.1: negative INTEGER not allowed in ECDSA signature');
        }
        // X.690 §10.4 — DER INTEGER must use the minimum number of contents
        // octets. A leading 0x00 is only allowed when the next byte has its
        // high bit set (i.e., the 0x00 is genuinely needed to disambiguate
        // from a negative two's-complement value).
        if (strlen($bytes) >= 2 && $bytes[0] === "\x00") {
            if ((ord($bytes[1]) & 0x80) === 0) {
                throw new InvalidKeyException('ASN.1: non-canonical INTEGER (redundant leading 0x00 byte)');
            }
            $bytes = substr($bytes, 1);
        }

        return $bytes;
    }

    /**
     * @throws InvalidKeyException
     */
    private static function readLength(string $der, int &$offset): int
    {
        if (!isset($der[$offset])) {
            throw new InvalidKeyException('ASN.1: unexpected end of input (expected length)');
        }
        $first = ord($der[$offset++]);
        if (($first & 0x80) === 0) {
            return $first;
        }
        $numBytes = $first & 0x7F;
        if ($numBytes === 0 || $numBytes > 4) {
            throw new InvalidKeyException(sprintf('ASN.1: unsupported length encoding (0x%02X)', $first));
        }
        if ($offset + $numBytes > strlen($der)) {
            throw new InvalidKeyException('ASN.1: length bytes extend past buffer');
        }
        // X.690 §10.1 — long form must not have a leading 0x00 octet.
        if ($numBytes > 1 && $der[$offset] === "\x00") {
            throw new InvalidKeyException('ASN.1: non-canonical length (long-form has leading 0x00 octet)');
        }
        $length = 0;
        for ($i = 0; $i < $numBytes; $i++) {
            $length = ($length << 8) | ord($der[$offset++]);
        }
        // X.690 §10.1 — short form must be used whenever length < 128.
        if ($length < 0x80) {
            throw new InvalidKeyException('ASN.1: non-canonical length (long-form used for value < 128)');
        }

        return $length;
    }

    /**
     * @param positive-int $size
     *
     * @return non-empty-string exactly `$size` bytes
     *
     * @throws InvalidKeyException
     */
    private static function leftPad(string $bytes, int $size): string
    {
        if (strlen($bytes) > $size) {
            throw new InvalidKeyException(sprintf('ECDSA component (%d bytes) exceeds curve coord size (%d)', strlen($bytes), $size));
        }

        return str_pad($bytes, $size, "\x00", STR_PAD_LEFT);
    }
}
