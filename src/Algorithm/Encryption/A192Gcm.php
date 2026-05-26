<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Encryption;

/**
 * A192GCM content encryption (RFC 7518 §5.3) — AES-192 in Galois/Counter Mode.
 */
final class A192Gcm extends AesGcm
{
    public function name(): string
    {
        return 'A192GCM';
    }

    public function cekByteLength(): int
    {
        return 24;
    }

    protected function opensslCipher(): string
    {
        return 'aes-192-gcm';
    }
}
