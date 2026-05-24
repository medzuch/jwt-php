<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

use Medzuch\Jwt\Key\Internal\EcCurve;

/**
 * ECDSA using P-521 and SHA-512 (RFC 7518 §3.4).
 *
 * Note: the curve is P-**521** (521-bit order) but the algorithm name is
 * ES**512**, because the hash is SHA-512. The component size is 66 bytes
 * (⌈521/8⌉), not 64.
 */
final class Es512 extends EcdsaSigningAlgorithm
{
    public function name(): string
    {
        return 'ES512';
    }

    protected function opensslAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }

    protected function curve(): EcCurve
    {
        return EcCurve::fromJwkName('P-521');
    }
}
