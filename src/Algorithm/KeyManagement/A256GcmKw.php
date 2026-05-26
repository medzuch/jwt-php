<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

/**
 * `A256GCMKW` — AES-GCM Key Wrap with a 256-bit key (RFC 7518 §4.7).
 */
final class A256GcmKw extends AesGcmKw
{
    public function name(): string
    {
        return 'A256GCMKW';
    }

    protected function opensslCipher(): string
    {
        return 'aes-256-gcm';
    }
}
