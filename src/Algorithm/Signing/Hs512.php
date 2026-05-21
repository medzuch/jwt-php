<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

/**
 * HMAC-SHA-512 (RFC 7518 §3.2).
 */
final class Hs512 extends HmacAlgorithm
{
    public function name(): string
    {
        return 'HS512';
    }

    protected function hashAlgorithm(): string
    {
        return 'sha512';
    }
}
