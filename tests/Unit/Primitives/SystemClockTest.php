<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Primitives;

use Medzuch\Jwt\Primitives\SystemClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SystemClock::class)]
final class SystemClockTest extends TestCase
{
    public function testNowIsInUtc(): void
    {
        $now = (new SystemClock())->now();

        self::assertSame('UTC', $now->getTimezone()->getName());
    }

    public function testNowMovesForward(): void
    {
        $clock = new SystemClock();
        $a = $clock->now();
        usleep(1_500); // 1.5 ms; well above DateTimeImmutable's microsecond resolution
        $b = $clock->now();

        self::assertGreaterThanOrEqual($a, $b);
    }
}
