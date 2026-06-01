<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

/**
 * `A128GCMKW` — AES-GCM Key Wrap with a 128-bit key (RFC 7518 §4.7).
 */
final class A128GcmKw extends AesGcmKw
{
    public function name(): string
    {
        return 'A128GCMKW';
    }

    protected function opensslCipher(): string
    {
        return 'aes-128-gcm';
    }
}
