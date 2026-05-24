<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

/**
 * RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (RFC 7518 §3.5).
 *
 * Salt length is hLen = 64 bytes.
 */
final class Ps512 extends PssSigningAlgorithm
{
    public function name(): string
    {
        return 'PS512';
    }

    protected function hashAlgorithm(): string
    {
        return 'sha512';
    }

    protected function hashByteLength(): int
    {
        return 64;
    }
}
