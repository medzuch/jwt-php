<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

/**
 * HMAC-SHA-256 (RFC 7518 §3.2).
 */
final class Hs256 extends HmacAlgorithm
{
    public function name(): string
    {
        return 'HS256';
    }

    protected function hashAlgorithm(): string
    {
        return 'sha256';
    }
}
