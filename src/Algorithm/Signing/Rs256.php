<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

/**
 * RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 §3.3).
 */
final class Rs256 extends RsaSigningAlgorithm
{
    public function name(): string
    {
        return 'RS256';
    }

    protected function opensslAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }
}
