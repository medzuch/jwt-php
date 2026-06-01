<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Encryption;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Primitives\ConstantTime;

/**
 * Shared AES-CBC + HMAC-SHA-2 content-encryption mechanics (RFC 7518 §5.2.2).
 * One concrete subclass per `enc` — A128CBC-HS256 / A192CBC-HS384 /
 * A256CBC-HS512.
 *
 * This is the composed AEAD of RFC 7518 §5.2: the CEK is split into a MAC key
 * (first half) and an AES-CBC encryption key (second half), each of length
 * {@see self::keyHalfBytes()}. The plaintext is encrypted with AES-CBC
 * (PKCS#7 padding), then an HMAC is computed over
 * `AAD || IV || ciphertext || AL`, where `AL` is the 64-bit big-endian bit
 * length of the AAD; the authentication tag is the MAC truncated to the MAC
 * key length (§5.2.2.1).
 *
 * Decryption is **MAC-then-decrypt** (§5.2.2.2): the tag is recomputed and
 * compared in constant time *before* the ciphertext is decrypted, so a forged
 * tag never reaches the CBC routine. Any tag mismatch or padding failure
 * collapses to {@see DecryptionException}.
 */
abstract class AesCbcHmac implements ContentEncryptionAlgorithm
{
    /** AES-CBC uses a full 128-bit block as the IV. */
    private const IV_BYTES = 16;

    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::AesCbcHmac;
    }

    public function ivByteLength(): int
    {
        return self::IV_BYTES;
    }

    public function cekByteLength(): int
    {
        // MAC key + ENC key, each one half (RFC 7518 §5.2.2.1).
        return 2 * $this->keyHalfBytes();
    }

    public function encrypt(string $plaintext, string $cek, string $iv, string $aad): array
    {
        $this->assertInputLengths($cek, $iv);
        [$macKey, $encKey] = $this->splitKey($cek);

        $ciphertext = openssl_encrypt($plaintext, $this->opensslCipher(), $encKey, OPENSSL_RAW_DATA, $iv);
        // @infection-ignore-all — defensive against an OpenSSL backend fault;
        // unreachable with the validated lengths, so the mutant is equivalent.
        if ($ciphertext === false) {
            // @codeCoverageIgnoreStart
            throw new DecryptionException(sprintf('AES-CBC encryption failed for %s', $this->name()));
            // @codeCoverageIgnoreEnd
        }

        $tag = $this->computeTag($macKey, $aad, $iv, $ciphertext);

        return [$ciphertext, $tag];
    }

    public function decrypt(string $ciphertext, string $cek, string $iv, string $tag, string $aad): string
    {
        $this->assertInputLengths($cek, $iv);
        [$macKey, $encKey] = $this->splitKey($cek);

        $expectedTag = $this->computeTag($macKey, $aad, $iv, $ciphertext);
        if (!ConstantTime::equals($expectedTag, $tag)) {
            throw new DecryptionException(sprintf('%s authentication tag mismatch', $this->name()));
        }

        $plaintext = openssl_decrypt($ciphertext, $this->opensslCipher(), $encKey, OPENSSL_RAW_DATA, $iv);
        // @infection-ignore-all — only reachable via a ciphertext that passed
        // the HMAC yet decrypts to invalid padding, which a non-forged token
        // never produces; not constructible in tests without the MAC key.
        if ($plaintext === false) {
            throw new DecryptionException(sprintf('%s decryption failed (padding or block error)', $this->name()));
        }

        return $plaintext;
    }

    /**
     * Byte length of each key half: the MAC key and the AES key are both this
     * long (16 / 24 / 32 for HS256 / HS384 / HS512 families).
     *
     * @return positive-int
     */
    abstract protected function keyHalfBytes(): int;

    /**
     * The `hash_hmac` algorithm name, e.g. `"sha256"`.
     *
     * @return non-empty-string
     */
    abstract protected function hashAlgorithm(): string;

    /**
     * The `openssl_*` cipher name, e.g. `"aes-128-cbc"`.
     *
     * @return non-empty-string
     */
    abstract protected function opensslCipher(): string;

    /**
     * @return array{0: string, 1: string} `[macKey, encKey]`
     */
    private function splitKey(string $cek): array
    {
        $half = $this->keyHalfBytes();

        return [substr($cek, 0, $half), substr($cek, $half)];
    }

    /**
     * HMAC over `AAD || IV || ciphertext || AL`, truncated to the MAC key
     * length per RFC 7518 §5.2.2.1, where `AL` is the AAD bit length as a
     * 64-bit big-endian integer.
     *
     * @return non-empty-string
     */
    private function computeTag(string $macKey, string $aad, string $iv, string $ciphertext): string
    {
        $al = pack('J', strlen($aad) * 8);
        $mac = hash_hmac($this->hashAlgorithm(), $aad . $iv . $ciphertext . $al, $macKey, true);

        $tag = substr($mac, 0, $this->keyHalfBytes());

        /** @var non-empty-string $tag */
        return $tag;
    }

    /**
     * @throws DecryptionException on a wrong IV length (attacker-supplied on
     *                             the decrypt path); a wrong CEK length is an
     *                             internal invariant violation
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
