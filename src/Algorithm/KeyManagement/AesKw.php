<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\CekEncryptionResult;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementMode;
use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Primitives\Random;

/**
 * Shared AES Key Wrap mechanics (RFC 7518 §4.4) — one concrete subclass per
 * `alg`: A128KW / A192KW / A256KW.
 *
 * Unlike `dir`, key wrapping uses a *fresh, random* Content Encryption Key for
 * every message; the recipient's shared key acts as a Key Encryption Key (KEK)
 * that wraps the CEK with the NIST/RFC 3394 AES Key Wrap algorithm. The wrapped
 * CEK travels as the JWE Encrypted Key (the second compact segment); no
 * per-recipient header parameters are needed.
 *
 * AES Key Wrap is its own authenticated primitive: it carries a 64-bit
 * integrity register seeded with the RFC 3394 default IV
 * (`A6A6A6A6A6A6A6A6`), and unwrapping verifies it. OpenSSL's `aes-*-wrap`
 * ciphers implement exactly this when handed that IV explicitly — a tampered
 * or wrong-KEK Encrypted Key fails the integrity check and `openssl_decrypt`
 * returns `false`, which collapses to {@see DecryptionException}.
 */
abstract class AesKw implements KeyManagementAlgorithm
{
    /**
     * RFC 3394 §2.2.3.1 default Initial Value — the 64-bit integrity register
     * AES Key Wrap is seeded with. OpenSSL's `aes-*-wrap` ciphers reproduce the
     * standard wrap only when this exact IV is supplied (an empty IV makes
     * OpenSSL substitute a non-standard value that round-trips but is not
     * interoperable).
     */
    private const DEFAULT_IV = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";

    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::AesKw;
    }

    public function mode(): KeyManagementMode
    {
        return KeyManagementMode::KeyWrapping;
    }

    public function encryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption): CekEncryptionResult
    {
        $kek = $this->kek($recipientKey, 'wrapKey');
        $cek = Random::bytes($contentEncryption->cekByteLength());

        $wrapped = openssl_encrypt($cek, $this->opensslCipher(), $kek, OPENSSL_RAW_DATA, self::DEFAULT_IV);
        // @infection-ignore-all — defence against an OpenSSL backend fault; with
        // a validated KEK length and a CEK of the algorithm's required size it
        // cannot be triggered from tests, so the mutant is equivalent.
        if (!is_string($wrapped) || $wrapped === '') {
            // @codeCoverageIgnoreStart
            throw new DecryptionException(sprintf('AES Key Wrap failed for %s', $this->name()));
            // @codeCoverageIgnoreEnd
        }

        return new CekEncryptionResult($cek, $wrapped);
    }

    public function decryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption, string $encryptedKey, array $header): string
    {
        $kek = $this->kek($recipientKey, 'unwrapKey');

        $cek = openssl_decrypt($encryptedKey, $this->opensslCipher(), $kek, OPENSSL_RAW_DATA, self::DEFAULT_IV);
        if (!is_string($cek) || $cek === '') {
            // A failed integrity check, a wrong KEK, or a malformed Encrypted
            // Key all surface here as `false`; none must leak which.
            throw new DecryptionException(sprintf('%s key unwrap failed (integrity check or malformed Encrypted Key)', $this->name()));
        }

        return $cek;
    }

    /**
     * The `openssl_*` cipher name backing this `alg`, e.g. `"aes-128-wrap"`.
     *
     * @return non-empty-string
     */
    abstract protected function opensslCipher(): string;

    /**
     * Narrow the recipient key to an {@see OctKey} bound to *this* wrapping
     * algorithm and permitted to perform the wrap/unwrap operation.
     *
     * @return non-empty-string the raw KEK bytes
     *
     * @throws KeyMismatchException
     */
    private function kek(Key $key, string $op): string
    {
        if (!$key instanceof OctKey) {
            throw new KeyMismatchException(sprintf('%s requires an OctKey; got %s (RFC 8725 §3.1)', $this->name(), $key::class));
        }

        // The KEK is bound to the key-management algorithm itself (e.g.
        // "A128KW"), not to the content `enc`.
        $key->assertAlgorithm($this->name());

        if (!$key->allowsOperation($op)) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "%s" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)', $op));
        }

        return $key->bytes();
    }
}
