<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Encryption;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Exception\DecryptionException;

/**
 * Shared AES-GCM content-encryption mechanics (RFC 7518 §5.3). One concrete
 * subclass per `enc` — A128GCM / A192GCM / A256GCM — differing only in the
 * AES key size.
 *
 * GCM is a single-pass AEAD: `openssl_encrypt` produces the ciphertext and a
 * 16-octet authentication tag over the AAD; `openssl_decrypt` returns `false`
 * on any tampering, which collapses to {@see DecryptionException}. The IV is
 * the JOSE-mandated 96 bits (12 octets, RFC 7518 §5.3).
 */
abstract class AesGcm implements ContentEncryptionAlgorithm
{
    /** GCM uses a 96-bit IV and a 128-bit tag throughout the JOSE registry. */
    private const IV_BYTES = 12;
    private const TAG_BYTES = 16;

    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::AesGcm;
    }

    public function ivByteLength(): int
    {
        return self::IV_BYTES;
    }

    public function encrypt(string $plaintext, string $cek, string $iv, string $aad): array
    {
        $this->assertInputLengths($cek, $iv);

        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, $this->opensslCipher(), $cek, OPENSSL_RAW_DATA, $iv, $tag, $aad, self::TAG_BYTES);
        // @infection-ignore-all — the guard is defence against an OpenSSL
        // backend fault; with the key/IV lengths asserted above it cannot be
        // triggered from tests, so its mutants are equivalent.
        if ($ciphertext === false || !is_string($tag) || strlen($tag) !== self::TAG_BYTES) {
            // @codeCoverageIgnoreStart
            // Unreachable with the validated key/IV lengths asserted above;
            // a failure here is an OpenSSL backend fault, not attacker input.
            throw new DecryptionException(sprintf('AES-GCM encryption failed for %s', $this->name()));
            // @codeCoverageIgnoreEnd
        }

        return [$ciphertext, $tag];
    }

    public function decrypt(string $ciphertext, string $cek, string $iv, string $tag, string $aad): string
    {
        $this->assertInputLengths($cek, $iv);

        $plaintext = openssl_decrypt($ciphertext, $this->opensslCipher(), $cek, OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if ($plaintext === false) {
            throw new DecryptionException(sprintf('AES-GCM authentication/decryption failed for %s', $this->name()));
        }

        return $plaintext;
    }

    /**
     * The `openssl_*` cipher name backing this `enc`, e.g. `"aes-128-gcm"`.
     *
     * @return non-empty-string
     */
    abstract protected function opensslCipher(): string;

    /**
     * @throws DecryptionException if the IV length is wrong (attacker-supplied
     *                             on the decrypt path); a wrong CEK length is
     *                             an internal invariant violation
     */
    private function assertInputLengths(string $cek, string $iv): void
    {
        if (strlen($iv) !== self::IV_BYTES) {
            throw new DecryptionException(sprintf('%s requires a %d-byte IV; got %d', $this->name(), self::IV_BYTES, strlen($iv)));
        }
        // @infection-ignore-all — the CEK length is an internal invariant the
        // key-management layer guarantees; this guard is defensive and cannot
        // be reached from tests.
        if (strlen($cek) !== $this->cekByteLength()) {
            // @codeCoverageIgnoreStart
            throw new DecryptionException(sprintf('%s requires a %d-byte key; got %d', $this->name(), $this->cekByteLength(), strlen($cek)));
            // @codeCoverageIgnoreEnd
        }
    }
}
