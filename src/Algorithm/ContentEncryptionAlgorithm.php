<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm;

use Medzuch\Jwt\Exception\DecryptionException;

/**
 * Contract for JWE content-encryption (`enc`) algorithms — the AEAD that
 * protects the plaintext with the Content Encryption Key (RFC 7518 §5).
 *
 * These operate on raw byte strings, never {@see \Medzuch\Jwt\Key\Key}
 * objects: the CEK is either generated fresh by the {@see \Medzuch\Jwt\Jwe\Encrypter}
 * or recovered by a key-management algorithm, so by the time it reaches an
 * `enc` algorithm it is just `cekByteLength()` octets. The IV is likewise
 * raw bytes the Encrypter generates per RFC 7518 (`ivByteLength()` octets).
 *
 * The Additional Authenticated Data (`$aad`) is the ASCII octets of
 * `BASE64URL(UTF8(JWE Protected Header))` (RFC 7516 §5.1 step 14) — the
 * content algorithm authenticates it but does not encrypt it.
 *
 * Symmetry with {@see SigningAlgorithm}: `decrypt()` throws
 * {@see DecryptionException} on an authentication-tag mismatch rather than
 * returning a sentinel, because a failed tag is a fail-closed security event,
 * not an ordinary boolean outcome.
 */
interface ContentEncryptionAlgorithm extends Algorithm
{
    /**
     * Exact Content Encryption Key length this algorithm requires, in bytes
     * (e.g. 16 for A128GCM, 32 for A128CBC-HS256 — CBC-HS doubles the key to
     * carry a MAC half, RFC 7518 §5.2.2.1).
     *
     * @return positive-int
     */
    public function cekByteLength(): int;

    /**
     * Initialization Vector length this algorithm requires, in bytes
     * (12 for the GCM family, 16 for the CBC-HS family).
     *
     * @return positive-int
     */
    public function ivByteLength(): int;

    /**
     * Encrypt `$plaintext` under `$cek` and `$iv`, authenticating `$aad`.
     *
     * @param string $cek exactly {@see self::cekByteLength()} octets
     * @param string $iv  exactly {@see self::ivByteLength()} octets
     *
     * @return array{0: string, 1: non-empty-string} `[ciphertext, authentication tag]`
     */
    public function encrypt(string $plaintext, string $cek, string $iv, string $aad): array;

    /**
     * Authenticate and decrypt `$ciphertext`.
     *
     * @param string $cek exactly {@see self::cekByteLength()} octets
     * @param string $iv  exactly {@see self::ivByteLength()} octets
     *
     * @throws DecryptionException on a tag mismatch, malformed input, or backend failure
     */
    public function decrypt(string $ciphertext, string $cek, string $iv, string $tag, string $aad): string;
}
