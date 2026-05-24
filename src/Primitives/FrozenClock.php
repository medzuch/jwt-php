<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Primitives;

use DateInterval;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * PSR-20 clock pinned to a caller-chosen instant; useful in tests so that
 * `exp` and `nbf` boundary checks can be exercised deterministically.
 *
 * Mutable on purpose: tests need to advance time between assertions. The
 * library itself never stores a FrozenClock as state — it only consumes
 * the PSR-20 interface.
 */
final class FrozenClock implements ClockInterface
{
    public function __construct(private DateTimeImmutable $now) {}

    public static function at(string $iso8601): self
    {
        return new self(new DateTimeImmutable($iso8601));
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    public function tick(DateInterval $interval): void
    {
        $this->now = $this->now->add($interval);
    }

    public function setTo(DateTimeImmutable $instant): void
    {
        $this->now = $instant;
    }
}
