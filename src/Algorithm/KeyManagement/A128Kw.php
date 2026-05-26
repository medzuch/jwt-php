<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

/**
 * `A128KW` — AES Key Wrap with a 128-bit key (RFC 7518 §4.4).
 */
final class A128Kw extends AesKw
{
    public function name(): string
    {
        return 'A128KW';
    }

    protected function opensslCipher(): string
    {
        return 'aes-128-wrap';
    }
}
