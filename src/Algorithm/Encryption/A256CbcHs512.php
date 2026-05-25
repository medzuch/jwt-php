<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Encryption;

/**
 * A256CBC-HS512 (RFC 7518 §5.2.5) — AES-256-CBC with HMAC-SHA-512, 256-bit
 * tag. 64-byte CEK: 32-byte MAC key + 32-byte AES-256 key.
 */
final class A256CbcHs512 extends AesCbcHmac
{
    public function name(): string
    {
        return 'A256CBC-HS512';
    }

    protected function keyHalfBytes(): int
    {
        return 32;
    }

    protected function hashAlgorithm(): string
    {
        return 'sha512';
    }

    protected function opensslCipher(): string
    {
        return 'aes-256-cbc';
    }
}
