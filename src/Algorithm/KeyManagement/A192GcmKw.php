<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

/**
 * `A192GCMKW` — AES-GCM Key Wrap with a 192-bit key (RFC 7518 §4.7).
 */
final class A192GcmKw extends AesGcmKw
{
    public function name(): string
    {
        return 'A192GCMKW';
    }

    protected function opensslCipher(): string
    {
        return 'aes-192-gcm';
    }
}
