<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Primitives;

use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;

/**
 * Default PSR-20 clock — wall time in UTC.
 *
 * The validator and builder always work in UTC; if callers need a local
 * timezone they format on output.
 */
final class SystemClock implements ClockInterface
{
    private readonly DateTimeZone $utc;

    public function __construct()
    {
        $this->utc = new DateTimeZone('UTC');
    }

    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', $this->utc);
    }
}
