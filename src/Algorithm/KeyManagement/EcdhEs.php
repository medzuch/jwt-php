<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\CekEncryptionResult;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagement\Internal\EcdhKeyAgreement;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementMode;
use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Key\Key;

/**
 * `ECDH-ES` — Elliptic Curve Diffie-Hellman Ephemeral Static, Direct Key
 * Agreement mode (RFC 7518 §4.6). The Concat-KDF output of the agreement *is*
 * the Content Encryption Key, so — like `dir` — there is no JWE Encrypted Key.
 *
 * The derived key is sized to the content-encryption algorithm's CEK, and the
 * Concat KDF's AlgorithmID is the `enc` value (RFC 7518 §4.6.2). The ephemeral
 * public key is contributed as the `epk` protected-header parameter.
 *
 * Note: this library's encryption path always uses empty `apu`/`apv`
 * (PartyUInfo/PartyVInfo); the decryption path honours any present in the
 * token, so it interoperates with senders that set them.
 */
final class EcdhEs implements KeyManagementAlgorithm
{
    public function name(): string
    {
        return 'ECDH-ES';
    }

    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::EcdhEs;
    }

    public function mode(): KeyManagementMode
    {
        return KeyManagementMode::DirectKeyAgreement;
    }

    /**
     * Agreement uses only the recipient's public point, so `$recipientKey` may
     * be an {@see \Medzuch\Jwt\Key\EcPublicKey} or an
     * {@see \Medzuch\Jwt\Key\EcPrivateKey} (its public part is taken).
     */
    public function encryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption): CekEncryptionResult
    {
        [$cek, $header] = EcdhKeyAgreement::deriveSenderKey(
            $recipientKey,
            $this->name(),
            $contentEncryption->name(),
            $contentEncryption->cekByteLength(),
        );

        return new CekEncryptionResult($cek, '', $header);
    }

    public function decryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption, string $encryptedKey, array $header): string
    {
        if ($encryptedKey !== '') {
            // RFC 7516 §4.5 / §4.6: direct key agreement carries no Encrypted
            // Key. A non-empty one signals a malformed or manipulated token.
            throw new DecryptionException('An "ECDH-ES" (direct) JWE must not carry a JWE Encrypted Key');
        }

        return EcdhKeyAgreement::deriveRecipientKey(
            $recipientKey,
            $header,
            $this->name(),
            $contentEncryption->name(),
            $contentEncryption->cekByteLength(),
        );
    }
}
