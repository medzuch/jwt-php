<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Primitives;

use InvalidArgumentException;
use Medzuch\Jwt\Primitives\Random;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Random::class)]
final class RandomTest extends TestCase
{
    #[DataProvider('positiveLengthProvider')]
    public function testReturnsBytesOfRequestedLength(int $length): void
    {
        self::assertSame($length, strlen(Random::bytes($length)));
    }

    /** @return iterable<string, array{int}> */
    public static function positiveLengthProvider(): iterable
    {
        yield 'one' => [1];
        yield 'sixteen' => [16];
        yield 'thirty-two (HS256 key size)' => [32];
        yield 'sixty-four (HS512 key size)' => [64];
    }

    #[DataProvider('nonPositiveLengthProvider')]
    public function testRejectsNonPositiveLength(int $length): void
    {
        $this->expectException(InvalidArgumentException::class);

        Random::bytes($length);
    }

    /** @return iterable<string, array{int}> */
    public static function nonPositiveLengthProvider(): iterable
    {
        yield 'zero' => [0];
        yield 'negative one' => [-1];
        yield 'large negative' => [-1024];
    }

    public function testTwoCallsReturnDifferentBytes(): void
    {
        // Not a randomness test — just confirms we're not returning a
        // constant. random_bytes' actual quality is the kernel's problem.
        self::assertNotSame(Random::bytes(32), Random::bytes(32));
    }
}
