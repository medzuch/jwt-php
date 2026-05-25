<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Encryption;

/**
 * A128GCM content encryption (RFC 7518 §5.3) — AES-128 in Galois/Counter Mode.
 */
final class A128Gcm extends AesGcm
{
    public function name(): string
    {
        return 'A128GCM';
    }

    public function cekByteLength(): int
    {
        return 16;
    }

    protected function opensslCipher(): string
    {
        return 'aes-128-gcm';
    }
}
