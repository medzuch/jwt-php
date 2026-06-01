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
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Random;
use Throwable;

/**
 * Shared AES-GCM Key Wrap mechanics (RFC 7518 §4.7) — one concrete subclass
 * per `alg`: A128GCMKW / A192GCMKW / A256GCMKW.
 *
 * Like {@see AesKw}, a fresh random CEK is wrapped under the recipient's shared
 * Key Encryption Key; here the wrapping primitive is AES-GCM. GCM is a
 * single-pass AEAD, so wrapping yields both the wrapped CEK (the JWE Encrypted
 * Key) *and* two per-recipient header parameters the recipient needs to
 * unwrap: the 96-bit Initialization Vector (`iv`) and the 128-bit
 * Authentication Tag (`tag`), each base64url-encoded (RFC 7518 §4.7.1). The
 * Additional Authenticated Data for this GCM operation is the empty octet
 * string — the wrap does not authenticate the JWE header, which the
 * content-encryption layer covers separately.
 *
 * On decrypt, a tampered Encrypted Key, `iv`, or `tag` fails GCM
 * authentication and `openssl_decrypt` returns `false`, collapsing to
 * {@see DecryptionException}.
 */
abstract class AesGcmKw implements KeyManagementAlgorithm
{
    /** GCM uses a 96-bit IV and a 128-bit tag throughout the JOSE registry. */
    private const IV_BYTES = 12;
    private const TAG_BYTES = 16;

    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::AesGcmKw;
    }

    public function mode(): KeyManagementMode
    {
        return KeyManagementMode::KeyWrapping;
    }

    public function encryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption): CekEncryptionResult
    {
        $kek = $this->kek($recipientKey, 'wrapKey');
        $cek = Random::bytes($contentEncryption->cekByteLength());
        $iv = Random::bytes(self::IV_BYTES);

        $tag = '';
        $wrapped = openssl_encrypt($cek, $this->opensslCipher(), $kek, OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_BYTES);
        // @infection-ignore-all — defence against an OpenSSL backend fault;
        // unreachable with the validated KEK/IV lengths, so the mutant is
        // equivalent.
        if (!is_string($wrapped) || $wrapped === '' || !is_string($tag) || strlen($tag) !== self::TAG_BYTES) {
            // @codeCoverageIgnoreStart
            throw new DecryptionException(sprintf('AES-GCM key wrap failed for %s', $this->name()));
            // @codeCoverageIgnoreEnd
        }

        return new CekEncryptionResult($cek, $wrapped, [
            'iv' => Base64Url::encode($iv),
            'tag' => Base64Url::encode($tag),
        ]);
    }

    public function decryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption, string $encryptedKey, array $header): string
    {
        $kek = $this->kek($recipientKey, 'unwrapKey');
        $iv = $this->headerBytes($header, 'iv', self::IV_BYTES);
        $tag = $this->headerBytes($header, 'tag', self::TAG_BYTES);

        $cek = openssl_decrypt($encryptedKey, $this->opensslCipher(), $kek, OPENSSL_RAW_DATA, $iv, $tag, '');
        if (!is_string($cek) || $cek === '') {
            throw new DecryptionException(sprintf('%s key unwrap failed (authentication or malformed Encrypted Key)', $this->name()));
        }

        return $cek;
    }

    /**
     * The `openssl_*` cipher name backing this `alg`, e.g. `"aes-128-gcm"`.
     *
     * @return non-empty-string
     */
    abstract protected function opensslCipher(): string;

    /**
     * Decode and length-check a base64url header parameter (`iv` / `tag`) the
     * recipient needs to unwrap. A missing, non-string, or wrong-length value
     * is attacker-controlled input on the decrypt path and must fail closed.
     *
     * @param array<string, mixed> $header
     *
     * @throws DecryptionException
     */
    private function headerBytes(array $header, string $param, int $expectedLength): string
    {
        $value = $header[$param] ?? null;
        if (!is_string($value) || $value === '') {
            throw new DecryptionException(sprintf('%s JWE is missing the "%s" header parameter', $this->name(), $param));
        }

        try {
            $bytes = Base64Url::decode($value);
        } catch (Throwable $e) {
            throw new DecryptionException(sprintf('%s "%s" header parameter is not valid base64url', $this->name(), $param), 0, $e);
        }

        if (strlen($bytes) !== $expectedLength) {
            throw new DecryptionException(sprintf('%s "%s" must be %d bytes; got %d', $this->name(), $param, $expectedLength, strlen($bytes)));
        }

        return $bytes;
    }

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

        $key->assertAlgorithm($this->name());

        if (!$key->allowsOperation($op)) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "%s" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)', $op));
        }

        return $key->bytes();
    }
}
