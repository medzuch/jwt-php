<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Benchmarks;

/**
 * A tiny adaptive micro-benchmark runner. Each operation is warmed up, then
 * run until a fixed wall-clock budget is spent, so fast ops (HMAC) and slow
 * ops (RSA signing) are both measured to comparable statistical confidence
 * without hand-tuning per-op iteration counts.
 *
 * Throughput is reported as operations per second; we also keep ns/op. The
 * runner asserts the operation does not throw, so a misconfigured scenario
 * fails loudly rather than silently reporting a no-op as "fast".
 */
final class Bench
{
    /** @var list<array{group: string, library: string, opsPerSec: float, nsPerOp: float, iterations: int}> */
    private array $results = [];

    public function __construct(
        private readonly float $budgetSeconds = 1.0,
        private readonly int $warmup = 100,
    ) {}

    public function run(string $group, string $library, callable $op): void
    {
        // Time-bounded warmup: at most `warmup` iterations, but never longer
        // than the budget. Cheap ops (HMAC) get the full iteration count to
        // warm the JIT/caches; expensive ops (pure-PHP RSA in some libraries)
        // bail out early instead of stalling for minutes before timing starts.
        $warmupDeadline = hrtime(true) + (int) ($this->budgetSeconds * 1_000_000_000);
        for ($i = 0; $i < $this->warmup; $i++) {
            $op();
            if (hrtime(true) >= $warmupDeadline) {
                break;
            }
        }

        $iterations = 0;
        $start = hrtime(true);
        $deadline = $start + (int) ($this->budgetSeconds * 1_000_000_000);

        // One op per deadline check, so a slow op (hundreds of ms) overshoots
        // the budget by at most one op rather than a whole unrolled batch. The
        // per-iteration hrtime() cost (~25ns) is uniform across libraries and
        // negligible beside the cheapest op measured (HMAC sign, ~1µs).
        do {
            $op();
            $iterations++;
        } while (hrtime(true) < $deadline);

        $elapsedNs = hrtime(true) - $start;
        $nsPerOp = $elapsedNs / $iterations;

        $this->results[] = [
            'group' => $group,
            'library' => $library,
            'opsPerSec' => 1_000_000_000 / $nsPerOp,
            'nsPerOp' => $nsPerOp,
            'iterations' => $iterations,
        ];
    }

    /** @return list<array{group: string, library: string, opsPerSec: float, nsPerOp: float, iterations: int}> */
    public function results(): array
    {
        return $this->results;
    }
}
