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

/**
 * `dir` — Direct Encryption (RFC 7518 §4.5). The shared symmetric key *is*
 * the Content Encryption Key; there is no JWE Encrypted Key.
 *
 * The recipient key is an {@see OctKey} bound to the content-encryption
 * algorithm (so an `A256GCM` key can only ever produce an `A256GCM` JWE —
 * the one-key-one-algorithm rule of RFC 8725 §3.1, here keyed on `enc`
 * rather than `alg`). {@see OctKey} already guarantees the byte length matches
 * the algorithm, so the bytes drop straight in as the CEK.
 */
final class Dir implements KeyManagementAlgorithm
{
    public function name(): string
    {
        return 'dir';
    }

    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::Direct;
    }

    public function mode(): KeyManagementMode
    {
        return KeyManagementMode::DirectEncryption;
    }

    public function encryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption): CekEncryptionResult
    {
        return new CekEncryptionResult($this->sharedKey($recipientKey, $contentEncryption, 'encrypt'), '');
    }

    public function decryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption, string $encryptedKey, array $header): string
    {
        if ($encryptedKey !== '') {
            // RFC 7516 §11 / §4.5: a `dir` JWE carries no Encrypted Key. A
            // non-empty one signals a malformed or manipulated token.
            throw new DecryptionException('A "dir" JWE must not carry a JWE Encrypted Key');
        }

        return $this->sharedKey($recipientKey, $contentEncryption, 'decrypt');
    }

    /**
     * @return non-empty-string
     *
     * @throws KeyMismatchException
     */
    private function sharedKey(Key $key, ContentEncryptionAlgorithm $contentEncryption, string $op): string
    {
        if (!$key instanceof OctKey) {
            throw new KeyMismatchException(sprintf('"dir" requires an OctKey; got %s (RFC 8725 §3.1)', $key::class));
        }

        // The shared key is bound to the content-encryption algorithm, not to
        // "dir": its bytes serve directly as that algorithm's CEK.
        $key->assertAlgorithm($contentEncryption->name());

        if (!$key->allowsOperation($op)) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "%s" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)', $op));
        }

        return $key->bytes();
    }
}
