<?php

declare(strict_types=1);

/**
 * Renders benchmark results as a Markdown table grouped by operation, with
 * each library's throughput (ops/sec) and a relative factor against the
 * fastest library in that row. Printed to stdout so the run can be piped into
 * docs/14-performance.md.
 *
 * @param list<array{group: string, library: string, opsPerSec: float, nsPerOp: float, iterations: int}> $results
 * @param list<string> $libraries
 */
function report(array $results, array $libraries, string $phpVersion): void
{
    // group => library => opsPerSec
    $byGroup = [];
    foreach ($results as $r) {
        $byGroup[$r['group']][$r['library']] = $r['opsPerSec'];
    }

    $shortName = static fn(string $lib): string => match ($lib) {
        'medzuch/jwt-php' => 'medzuch',
        'firebase/php-jwt' => 'firebase',
        'web-token/jwt-framework' => 'web-token',
        default => $lib,
    };

    echo "PHP {$phpVersion} · figures are operations/second (higher is better); ";
    echo "×N is throughput relative to the fastest library in that row.\n\n";

    $header = '| Operation |';
    $divider = '|---|';
    foreach ($libraries as $lib) {
        $header .= ' ' . $shortName($lib) . ' |';
        $divider .= '---|';
    }
    echo $header . "\n" . $divider . "\n";

    foreach ($byGroup as $group => $row) {
        $fastest = max($row);
        $line = "| $group |";
        foreach ($libraries as $lib) {
            $ops = $row[$lib] ?? null;
            if ($ops === null) {
                $line .= ' — |';
                continue;
            }
            $factor = $ops / $fastest;
            $line .= sprintf(' %s/s (×%.2f) |', fmt($ops), $factor);
        }
        echo $line . "\n";
    }

    echo "\n";
}

function fmt(float $opsPerSec): string
{
    if ($opsPerSec >= 1_000_000) {
        return sprintf('%.1fM', $opsPerSec / 1_000_000);
    }
    if ($opsPerSec >= 1_000) {
        return sprintf('%.0fk', $opsPerSec / 1_000);
    }

    return sprintf('%.0f', $opsPerSec);
}
