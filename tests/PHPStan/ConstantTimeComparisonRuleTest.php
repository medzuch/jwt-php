<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\PHPStan;

use Medzuch\Jwt\PHPStan\ConstantTimeComparisonRule;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PHPUnit\Framework\Attributes\CoversNothing;

/**
 * @extends RuleTestCase<ConstantTimeComparisonRule>
 */
#[CoversNothing]
final class ConstantTimeComparisonRuleTest extends RuleTestCase
{
    protected function getRule(): Rule
    {
        return new ConstantTimeComparisonRule();
    }

    public function testFlagsVariableTimeComparisonsOfSignatureMaterial(): void
    {
        $base = 'use ConstantTime::equals() / hash_equals() to avoid a timing side-channel (threat-model T12).';

        $this->analyse(
            [__DIR__ . '/data/ConstantTimeComparisonsFixture.php'],
            [
                ['Variable-time comparison (===) of likely signature/MAC value "signature"; ' . $base, 18],
                ['Variable-time comparison (!==) of likely signature/MAC value "expectedTag"; ' . $base, 22],
                ['Variable-time comparison (==) of likely signature/MAC value "mac"; ' . $base, 26],
            ],
        );
    }
}
