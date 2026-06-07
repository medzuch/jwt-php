<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\PHPStan\data;

/**
 * Fixture for {@see \Medzuch\Jwt\Tests\PHPStan\ConstantTimeComparisonRuleTest}.
 *
 * Contains deliberate timing-unsafe comparisons (flagged) alongside benign
 * ones (not flagged). Excluded from the main PHPStan run and from php-cs-fixer
 * — analysed only by the rule's own test.
 */
final class ConstantTimeComparisonsFixture
{
    public function flagged(string $signature, string $expected, string $tag, string $expectedTag): bool
    {
        if ($signature === $expected) {
            return true;
        }

        if ($expectedTag !== $tag) {
            return false;
        }

        return $this->mac() == $expected;
    }

    public function notFlagged(string $signature, ?string $sig, int $length): bool
    {
        // Presence / sentinel / length checks — not content comparisons.
        if ($signature === '') {
            return true;
        }

        if ($sig === null) {
            return false;
        }

        if ($length === 0) {
            return true;
        }

        $signatures = [];

        return $signatures === [];
    }

    public function notSensitive(string $kid, string $issuer): bool
    {
        // Names carry no signature/MAC semantics — out of scope for T12.
        return $kid === $issuer;
    }

    private function mac(): string
    {
        return '';
    }
}
