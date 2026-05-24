<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

use Medzuch\Jwt\Key\Internal\EcCurve;

/**
 * ECDSA using P-256 and SHA-256 (RFC 7518 §3.4).
 */
final class Es256 extends EcdsaSigningAlgorithm
{
    public function name(): string
    {
        return 'ES256';
    }

    protected function opensslAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    protected function curve(): EcCurve
    {
        return EcCurve::fromJwkName('P-256');
    }
}
