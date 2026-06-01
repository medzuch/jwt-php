<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm;

/**
 * The output of a {@see KeyManagementAlgorithm}'s encryption-side operation:
 * the Content Encryption Key the {@see \Medzuch\Jwt\Jwe\Encrypter} will use,
 * the JWE Encrypted Key octets to place in the second compact segment, and
 * any per-recipient header parameters the algorithm contributes.
 *
 * One uniform shape across all key-management modes (RFC 7518 §2):
 *   - `dir` — `cek` is the shared key, `encryptedKey` is empty, no header
 *     parameters.
 *   - AES key wrapping — `cek` is fresh and random, `encryptedKey` is the
 *     wrapped CEK; AES-GCM-KW additionally contributes `iv` / `tag`.
 *   - ECDH-ES direct — `cek` is agreement-derived, `encryptedKey` is empty,
 *     and `epk` is contributed.
 *   - ECDH-ES + key wrapping — agreement derives a KEK that wraps a random
 *     `cek`, with `epk` contributed.
 */
final readonly class CekEncryptionResult
{
    /**
     * @param non-empty-string     $cek              the Content Encryption Key
     * @param string               $encryptedKey     JWE Encrypted Key octets (empty for `dir` / ECDH-ES direct)
     * @param array<string, mixed> $headerParameters parameters this algorithm adds to the protected header
     */
    public function __construct(
        public string $cek,
        public string $encryptedKey,
        public array $headerParameters = [],
    ) {}
}
