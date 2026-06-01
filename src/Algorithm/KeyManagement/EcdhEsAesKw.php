<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\CekEncryptionResult;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagement\Internal\AesKeyWrap;
use Medzuch\Jwt\Algorithm\KeyManagement\Internal\EcdhKeyAgreement;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementMode;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Primitives\Random;

/**
 * `ECDH-ES+A128KW` / `+A192KW` / `+A256KW` — Key Agreement with Key Wrapping
 * (RFC 7518 §4.6). The ECDH-ES agreement derives a Key Encryption Key (sized
 * to the AES-KW variant, not to the content algorithm); that KEK then wraps a
 * fresh random CEK with AES Key Wrap.
 *
 * Two differences from direct {@see EcdhEs}: the Concat KDF's AlgorithmID is
 * the full `alg` value (e.g. `"ECDH-ES+A128KW"`) and `keydatalen` is the AES
 * key size; and the JWE Encrypted Key carries the wrapped CEK rather than
 * being empty.
 */
abstract class EcdhEsAesKw implements KeyManagementAlgorithm
{
    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::EcdhEs;
    }

    public function mode(): KeyManagementMode
    {
        return KeyManagementMode::KeyAgreementWithKeyWrapping;
    }

    public function encryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption): CekEncryptionResult
    {
        [$kek, $header] = EcdhKeyAgreement::deriveSenderKey($recipientKey, $this->name(), $this->name(), $this->kekByteLength());

        $cek = Random::bytes($contentEncryption->cekByteLength());
        $wrapped = AesKeyWrap::wrap($kek, $cek, $this->name());

        return new CekEncryptionResult($cek, $wrapped, $header);
    }

    public function decryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption, string $encryptedKey, array $header): string
    {
        $kek = EcdhKeyAgreement::deriveRecipientKey($recipientKey, $header, $this->name(), $this->name(), $this->kekByteLength());

        return AesKeyWrap::unwrap($kek, $encryptedKey, $this->name());
    }

    /**
     * The wrapping KEK length in bytes (16 / 24 / 32 for the 128 / 192 / 256
     * variants).
     *
     * @return positive-int
     */
    abstract protected function kekByteLength(): int;
}
