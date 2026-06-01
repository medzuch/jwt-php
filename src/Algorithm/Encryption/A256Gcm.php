<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Encryption;

/**
 * A256GCM content encryption (RFC 7518 §5.3) — AES-256 in Galois/Counter Mode.
 */
final class A256Gcm extends AesGcm
{
    public function name(): string
    {
        return 'A256GCM';
    }

    public function cekByteLength(): int
    {
        return 32;
    }

    protected function opensslCipher(): string
    {
        return 'aes-256-gcm';
    }
}
