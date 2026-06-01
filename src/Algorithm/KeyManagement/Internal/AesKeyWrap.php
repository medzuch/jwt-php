<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement\Internal;

use Medzuch\Jwt\Exception\DecryptionException;

/**
 * Raw AES Key Wrap (RFC 3394) over OpenSSL's `aes-*-wrap` ciphers, keyed by a
 * Key Encryption Key whose length selects the cipher (16/24/32 bytes →
 * 128/192/256-bit). Seeded with the RFC 3394 default IV (`A6A6…`), which is
 * what makes OpenSSL produce the standard, interoperable wrap.
 *
 * Shared by {@see \Medzuch\Jwt\Algorithm\KeyManagement\AesKw} (the `A*KW`
 * algorithms, whose KEK is a shared {@see \Medzuch\Jwt\Key\OctKey}) and the
 * `ECDH-ES+A*KW` algorithms (whose KEK is the Concat-KDF agreement output).
 *
 * @internal
 */
final class AesKeyWrap
{
    /** RFC 3394 §2.2.3.1 default Initial Value. */
    private const DEFAULT_IV = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";

    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * @param non-empty-string $kek
     *
     * @return non-empty-string the wrapped key
     *
     * @throws DecryptionException on a backend failure
     */
    public static function wrap(string $kek, string $plaintextKey, string $label): string
    {
        $wrapped = openssl_encrypt($plaintextKey, self::cipher($kek), $kek, OPENSSL_RAW_DATA, self::DEFAULT_IV);
        // @infection-ignore-all — defence against an OpenSSL backend fault;
        // unreachable with a validated KEK length, so the mutant is equivalent.
        if (!is_string($wrapped) || $wrapped === '') {
            // @codeCoverageIgnoreStart
            throw new DecryptionException(sprintf('AES Key Wrap failed for %s', $label));
            // @codeCoverageIgnoreEnd
        }

        return $wrapped;
    }

    /**
     * @param non-empty-string $kek
     *
     * @return non-empty-string the unwrapped key
     *
     * @throws DecryptionException on a failed integrity check or malformed input
     */
    public static function unwrap(string $kek, string $wrappedKey, string $label): string
    {
        $key = openssl_decrypt($wrappedKey, self::cipher($kek), $kek, OPENSSL_RAW_DATA, self::DEFAULT_IV);
        if (!is_string($key) || $key === '') {
            // A failed integrity check, a wrong KEK, or a malformed wrapped key
            // all surface as `false`; none must leak which.
            throw new DecryptionException(sprintf('%s key unwrap failed (integrity check or malformed Encrypted Key)', $label));
        }

        return $key;
    }

    /**
     * @param non-empty-string $kek
     *
     * @return non-empty-string
     */
    private static function cipher(string $kek): string
    {
        // @infection-ignore-all — KEK lengths are guaranteed by the bound key /
        // KDF output; the default arm is unreachable, so removing it is equivalent.
        return match (strlen($kek)) {
            16 => 'aes-128-wrap',
            24 => 'aes-192-wrap',
            32 => 'aes-256-wrap',
            // @codeCoverageIgnoreStart
            default => throw new DecryptionException(sprintf('AES Key Wrap KEK must be 16, 24, or 32 bytes; got %d', strlen($kek))),
            // @codeCoverageIgnoreEnd
        };
    }
}
