<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

/**
 * `A192KW` — AES Key Wrap with a 192-bit key (RFC 7518 §4.4).
 */
final class A192Kw extends AesKw
{
    public function name(): string
    {
        return 'A192KW';
    }
}
