<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Encryption;

/**
 * A192CBC-HS384 (RFC 7518 §5.2.4) — AES-192-CBC with HMAC-SHA-384, 192-bit
 * tag. 48-byte CEK: 24-byte MAC key + 24-byte AES-192 key.
 */
final class A192CbcHs384 extends AesCbcHmac
{
    public function name(): string
    {
        return 'A192CBC-HS384';
    }

    protected function keyHalfBytes(): int
    {
        return 24;
    }

    protected function hashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function opensslCipher(): string
    {
        return 'aes-192-cbc';
    }
}
