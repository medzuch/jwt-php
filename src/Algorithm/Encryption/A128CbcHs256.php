<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Encryption;

/**
 * A128CBC-HS256 (RFC 7518 §5.2.3) — AES-128-CBC with HMAC-SHA-256, 128-bit
 * tag. 32-byte CEK: 16-byte MAC key + 16-byte AES-128 key.
 */
final class A128CbcHs256 extends AesCbcHmac
{
    public function name(): string
    {
        return 'A128CBC-HS256';
    }

    protected function keyHalfBytes(): int
    {
        return 16;
    }

    protected function hashAlgorithm(): string
    {
        return 'sha256';
    }

    protected function opensslCipher(): string
    {
        return 'aes-128-cbc';
    }
}
