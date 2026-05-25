<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

use Medzuch\Jwt\Key\Internal\EcCurve;

/**
 * ECDSA using P-384 and SHA-384 (RFC 7518 §3.4).
 */
final class Es384 extends EcdsaSigningAlgorithm
{
    public function name(): string
    {
        return 'ES384';
    }

    protected function opensslAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }

    protected function curve(): EcCurve
    {
        return EcCurve::fromJwkName('P-384');
    }
}
