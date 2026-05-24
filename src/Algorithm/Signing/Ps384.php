<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

/**
 * RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (RFC 7518 §3.5).
 *
 * Salt length is hLen = 48 bytes.
 */
final class Ps384 extends PssSigningAlgorithm
{
    public function name(): string
    {
        return 'PS384';
    }

    protected function hashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function hashByteLength(): int
    {
        return 48;
    }
}
