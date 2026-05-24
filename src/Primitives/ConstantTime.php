<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Primitives;

/**
 * Constant-time byte-string comparison.
 *
 * The only place in the library that compares signature/MAC bytes. Using
 * `===` on signature material is a timing-leak (T12 in docs/02-threat-model.md);
 * route every such comparison through here.
 */
final class ConstantTime
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * Returns true iff the two strings are byte-identical, in time proportional
     * to the length of the longer string (not to the position of the first
     * differing byte).
     */
    public static function equals(string $known, string $candidate): bool
    {
        return hash_equals($known, $candidate);
    }
}
