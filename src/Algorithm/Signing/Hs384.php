<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

/**
 * HMAC-SHA-384 (RFC 7518 §3.2).
 */
final class Hs384 extends HmacAlgorithm
{
    public function name(): string
    {
        return 'HS384';
    }

    protected function hashAlgorithm(): string
    {
        return 'sha384';
    }
}
