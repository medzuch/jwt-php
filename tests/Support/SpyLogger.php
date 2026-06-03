<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Support;

use Psr\Log\AbstractLogger;
use Stringable;

/**
 * A PSR-3 logger that records every call for assertion in tests. Extends
 * {@see AbstractLogger} so the eight level shortcuts delegate to {@see log()}.
 *
 * @phpstan-type Record array{level: string, message: string, context: array<mixed>}
 */
final class SpyLogger extends AbstractLogger
{
    /** @var list<Record> */
    public array $records = [];

    /**
     * @param mixed             $level
     * @param array<mixed>      $context
     */
    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = [
            'level' => self::stringifyLevel($level),
            'message' => (string) $message,
            'context' => $context,
        ];
    }

    public function count(): int
    {
        return count($this->records);
    }

    /** @return Record */
    public function last(): array
    {
        $record = end($this->records);
        if ($record === false) {
            throw new \RuntimeException('SpyLogger recorded nothing');
        }

        return $record;
    }

    /** @return list<string> */
    public function levels(): array
    {
        return array_map(static fn(array $r): string => $r['level'], $this->records);
    }

    /** @param mixed $level */
    private static function stringifyLevel($level): string
    {
        return is_string($level) ? $level : (is_scalar($level) ? (string) $level : 'unknown');
    }
}
