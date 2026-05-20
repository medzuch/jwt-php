<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Primitives;

use InvalidArgumentException;

use function random_bytes;

/**
 * Cryptographically secure random bytes.
 *
 * Wraps `random_bytes` so call sites are easier to audit and easier to
 * stub in tests when needed.
 */
final class Random
{
    /** @codeCoverageIgnore */
    private function __construct()
    {
    }

    /**
     * @return non-empty-string
     *
     * @throws InvalidArgumentException if $length is less than 1
     */
    public static function bytes(int $length): string
    {
        if ($length < 1) {
            throw new InvalidArgumentException('Random::bytes length must be at least 1');
        }

        return random_bytes($length);
    }
}
