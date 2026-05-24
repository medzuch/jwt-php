<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

/**
 * RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (RFC 7518 §3.5).
 *
 * Salt length is hLen = 32 bytes.
 */
final class Ps256 extends PssSigningAlgorithm
{
    public function name(): string
    {
        return 'PS256';
    }

    protected function hashAlgorithm(): string
    {
        return 'sha256';
    }

    protected function hashByteLength(): int
    {
        return 32;
    }
}
