<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

use const OPENSSL_ALGO_SHA512;

/**
 * RSASSA-PKCS1-v1_5 using SHA-512 (RFC 7518 §3.3).
 */
final class Rs512 extends RsaSigningAlgorithm
{
    public function name(): string
    {
        return 'RS512';
    }

    protected function opensslAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }
}
