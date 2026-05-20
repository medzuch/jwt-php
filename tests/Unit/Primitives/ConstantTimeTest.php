<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Primitives;

use Medzuch\Jwt\Primitives\ConstantTime;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ConstantTime::class)]
final class ConstantTimeTest extends TestCase
{
    public function testReturnsTrueForIdenticalBytes(): void
    {
        self::assertTrue(ConstantTime::equals("\x01\x02\x03", "\x01\x02\x03"));
    }

    public function testReturnsFalseForDifferingBytes(): void
    {
        self::assertFalse(ConstantTime::equals("\x01\x02\x03", "\x01\x02\x04"));
    }

    public function testReturnsFalseForDifferingLengths(): void
    {
        self::assertFalse(ConstantTime::equals('abc', 'abcd'));
    }

    public function testEmptyStringsAreEqual(): void
    {
        self::assertTrue(ConstantTime::equals('', ''));
    }

    public function testEmptyVsNonEmptyIsUnequal(): void
    {
        self::assertFalse(ConstantTime::equals('', 'x'));
        self::assertFalse(ConstantTime::equals('x', ''));
    }
}
