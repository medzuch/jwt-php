<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing\Internal;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Exception\SignatureVerificationException;

/**
 * EMSA-PSS encoding / verification and MGF1 — RFC 8017 §9.1 + §B.2.1.
 *
 * Hand-rolled because PHP 8.3 + OpenSSL 3.x does not expose RSASSA-PSS
 * via `openssl_sign` (no algorithm name is accepted, the PSS padding
 * constant is not surfaced, and `openssl_private_encrypt` rejects PSS
 * padding). The path therefore is: build EM ourselves via EMSA-PSS,
 * then perform the raw RSA primitive via `openssl_private_encrypt` /
 * `openssl_public_decrypt` with `OPENSSL_NO_PADDING`.
 *
 * Defaults follow RFC 7518 §3.5: salt length equals hash output length
 * (sLen = hLen). MGF hash equals the main hash.
 *
 * @internal consumed by {@see \Medzuch\Jwt\Algorithm\Signing\PssSigningAlgorithm}
 */
final class Pss
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * EMSA-PSS-ENCODE (RFC 8017 §9.1.1).
     *
     * @param string $hashAlgo hash function name accepted by hash() (e.g. "sha256")
     * @param int    $emBits   intended bit length of the encoded message; for raw RSA
     *                         this is `modulus_bits - 1`
     * @param int    $sLen     salt length in bytes (RFC 7518 §3.5: sLen = hLen)
     *
     * @return string EM, exactly `ceil($emBits / 8)` bytes
     *
     * @throws SignatureVerificationException on parameter inconsistencies
     */
    public static function encode(string $message, string $hashAlgo, int $emBits, int $sLen): string
    {
        $hLen = self::hashLength($hashAlgo);
        $emLen = intdiv($emBits + 7, 8);

        if ($emLen < $hLen + $sLen + 2) {
            // @codeCoverageIgnoreStart — only reachable on impossibly small keys (< 1024-bit),
            // which RsaKey already rejects via MIN_BITS = 2048.
            throw new SignatureVerificationException(sprintf('PSS: emLen (%d) too small for hLen=%d sLen=%d', $emLen, $hLen, $sLen));
            // @codeCoverageIgnoreEnd
        }

        $mHash = hash($hashAlgo, $message, true);
        $salt = $sLen <= 0 ? '' : random_bytes($sLen);

        // M' = (0x00)^8 || mHash || salt
        $mPrime = str_repeat("\x00", 8) . $mHash . $salt;
        $h = hash($hashAlgo, $mPrime, true);

        // DB = PS || 0x01 || salt   where  PS = (0x00)^(emLen - sLen - hLen - 2)
        $db = str_repeat("\x00", $emLen - $sLen - $hLen - 2) . "\x01" . $salt;

        $dbMask = self::mgf1($h, $emLen - $hLen - 1, $hashAlgo);
        $maskedDB = $db ^ $dbMask;

        // Set leftmost (8*emLen - emBits) bits of leftmost octet of maskedDB to 0.
        $clearBits = 8 * $emLen - $emBits;
        if ($clearBits > 0) {
            $mask = 0xFF >> $clearBits;
            $maskedDB[0] = chr(ord($maskedDB[0]) & $mask);
        }

        return $maskedDB . $h . "\xbc";
    }

    /**
     * EMSA-PSS-VERIFY (RFC 8017 §9.1.2). Constant-time on the final hash
     * comparison.
     */
    public static function verify(string $message, string $em, string $hashAlgo, int $emBits, int $sLen): bool
    {
        $hLen = self::hashLength($hashAlgo);
        $emLen = intdiv($emBits + 7, 8);

        if (strlen($em) !== $emLen) {
            return false;
        }
        if ($emLen < $hLen + $sLen + 2) {
            // @codeCoverageIgnoreStart — see note in encode().
            return false;
            // @codeCoverageIgnoreEnd
        }
        // Trailer byte
        if ($em[$emLen - 1] !== "\xbc") {
            return false;
        }

        $maskedDB = substr($em, 0, $emLen - $hLen - 1);
        $h = substr($em, $emLen - $hLen - 1, $hLen);

        // Top bits of maskedDB must be zero (they were cleared during encode).
        $clearBits = 8 * $emLen - $emBits;
        if ($clearBits > 0) {
            $topMask = (0xFF << (8 - $clearBits)) & 0xFF;
            if ((ord($maskedDB[0]) & $topMask) !== 0) {
                return false;
            }
        }

        $dbMask = self::mgf1($h, $emLen - $hLen - 1, $hashAlgo);
        $db = $maskedDB ^ $dbMask;

        // Re-apply the high-bit clearing on the unmasked DB[0].
        if ($clearBits > 0) {
            $mask = 0xFF >> $clearBits;
            $db[0] = chr(ord($db[0]) & $mask);
        }

        $psLen = $emLen - $sLen - $hLen - 2;
        // PS = leftmost emLen - sLen - hLen - 2 octets must all be zero.
        for ($i = 0; $i < $psLen; $i++) {
            if ($db[$i] !== "\x00") {
                return false;
            }
        }
        // Followed by a single 0x01 octet.
        if ($db[$psLen] !== "\x01") {
            return false;
        }

        $salt = $sLen === 0 ? '' : substr($db, $psLen + 1, $sLen);

        $mHash = hash($hashAlgo, $message, true);
        $mPrime = str_repeat("\x00", 8) . $mHash . $salt;
        $hPrime = hash($hashAlgo, $mPrime, true);

        return hash_equals($h, $hPrime);
    }

    /**
     * MGF1 mask-generation function — RFC 8017 §B.2.1.
     *
     * @return string exactly `$maskLen` bytes
     */
    public static function mgf1(string $seed, int $maskLen, string $hashAlgo): string
    {
        $hLen = self::hashLength($hashAlgo);
        // RFC bound: maskLen ≤ 2^32 * hLen. PHP int is 64-bit on supported
        // platforms; in practice maskLen never exceeds a few hundred bytes
        // for PSS (emLen - hLen - 1 < 1024 for any reasonable RSA modulus).
        $iterations = intdiv($maskLen + $hLen - 1, $hLen);
        $output = '';
        for ($counter = 0; $counter < $iterations; $counter++) {
            $output .= hash($hashAlgo, $seed . pack('N', $counter), true);
        }

        return substr($output, 0, $maskLen);
    }

    /**
     * @return int hash output length in bytes
     */
    private static function hashLength(string $hashAlgo): int
    {
        return match ($hashAlgo) {
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
            default => throw new InvalidKeyException(sprintf('PSS: unsupported hash algorithm "%s"', $hashAlgo)),
        };
    }
}
