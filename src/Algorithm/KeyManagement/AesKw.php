<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\CekEncryptionResult;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagement\Internal\AesKeyWrap;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementMode;
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
 * that wraps the CEK with the NIST/RFC 3394 AES Key Wrap algorithm (see
 * {@see AesKeyWrap}). The wrapped CEK travels as the JWE Encrypted Key (the
 * second compact segment); no per-recipient header parameters are needed. The
 * concrete `alg` is fixed by the KEK length the bound {@see OctKey} enforces.
 *
 * AES Key Wrap is its own authenticated primitive: a tampered or wrong-KEK
 * Encrypted Key fails its integrity check, which collapses to
 * {@see \Medzuch\Jwt\Exception\DecryptionException}.
 */
abstract class AesKw implements KeyManagementAlgorithm
{
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

        return new CekEncryptionResult($cek, AesKeyWrap::wrap($kek, $cek, $this->name()));
    }

    public function decryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption, string $encryptedKey, array $header): string
    {
        $kek = $this->kek($recipientKey, 'unwrapKey');

        return AesKeyWrap::unwrap($kek, $encryptedKey, $this->name());
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

        // The KEK is bound to the key-management algorithm itself (e.g.
        // "A128KW"), not to the content `enc`.
        $key->assertAlgorithm($this->name());

        if (!$key->allowsOperation($op)) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "%s" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)', $op));
        }

        return $key->bytes();
    }
}
