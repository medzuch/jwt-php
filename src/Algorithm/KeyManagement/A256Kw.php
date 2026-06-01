<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

/**
 * `A256KW` — AES Key Wrap with a 256-bit key (RFC 7518 §4.4).
 */
final class A256Kw extends AesKw
{
    public function name(): string
    {
        return 'A256KW';
    }
}
