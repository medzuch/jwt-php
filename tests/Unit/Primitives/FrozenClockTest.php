<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Primitives;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Primitives\FrozenClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(FrozenClock::class)]
final class FrozenClockTest extends TestCase
{
    public function testReturnsPinnedInstant(): void
    {
        $clock = FrozenClock::at('2026-05-20T12:34:56Z');

        self::assertSame(
            '2026-05-20T12:34:56+00:00',
            $clock->now()->format(DATE_ATOM),
        );
    }

    public function testRepeatedCallsReturnSameInstant(): void
    {
        $clock = FrozenClock::at('2026-01-01T00:00:00Z');

        self::assertEquals($clock->now(), $clock->now());
    }

    public function testTickAdvancesTime(): void
    {
        $clock = FrozenClock::at('2026-01-01T00:00:00Z');
        $clock->tick(new DateInterval('PT30S'));

        self::assertSame(
            '2026-01-01T00:00:30+00:00',
            $clock->now()->format(DATE_ATOM),
        );
    }

    public function testSetToOverridesCurrentInstant(): void
    {
        $clock = FrozenClock::at('2026-01-01T00:00:00Z');
        $clock->setTo(new DateTimeImmutable('2030-12-31T23:59:59Z'));

        self::assertSame(
            '2030-12-31T23:59:59+00:00',
            $clock->now()->format(DATE_ATOM),
        );
    }
}
