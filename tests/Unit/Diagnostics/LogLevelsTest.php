<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Diagnostics;

use LogicException;
use Medzuch\Jwt\Diagnostics\LogLevels;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

#[CoversClass(LogLevels::class)]
final class LogLevelsTest extends TestCase
{
    public function testSecureDefaults(): void
    {
        $levels = new LogLevels();

        self::assertSame(LogLevel::DEBUG, $levels->accepted);
        self::assertSame(LogLevel::WARNING, $levels->verificationFailed);
        self::assertSame(LogLevel::NOTICE, $levels->claimRejected);
        self::assertSame(LogLevel::DEBUG, $levels->decrypted);
        self::assertSame(LogLevel::WARNING, $levels->decryptionFailed);
        self::assertSame(LogLevel::DEBUG, $levels->keyResolution);
        self::assertSame(LogLevel::WARNING, $levels->keyResolutionFailed);
    }

    public function testNamedOverridesAreIndependent(): void
    {
        $levels = new LogLevels(accepted: LogLevel::INFO, claimRejected: LogLevel::WARNING);

        self::assertSame(LogLevel::INFO, $levels->accepted);
        self::assertSame(LogLevel::WARNING, $levels->claimRejected);
        // Untouched fields keep their defaults.
        self::assertSame(LogLevel::WARNING, $levels->verificationFailed);
        self::assertSame(LogLevel::DEBUG, $levels->keyResolution);
    }

    public function testAllEnumeratesTheEightPsr3Levels(): void
    {
        self::assertCount(8, LogLevels::all());
        self::assertContains(LogLevel::EMERGENCY, LogLevels::all());
        self::assertContains(LogLevel::DEBUG, LogLevels::all());
    }

    /** @return iterable<string, array{string}> */
    public static function everyPsr3Level(): iterable
    {
        foreach (LogLevels::all() as $level) {
            yield $level => [$level];
        }
    }

    #[DataProvider('everyPsr3Level')]
    public function testEveryPsr3LevelIsAccepted(string $level): void
    {
        $levels = new LogLevels(accepted: $level);

        self::assertSame($level, $levels->accepted);
    }

    public function testUnknownLevelFailsFast(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Invalid PSR-3 log level "verbose" for "accepted"');

        new LogLevels(accepted: 'verbose');
    }

    public function testUppercaseLevelIsRejected(): void
    {
        // PSR-3 levels are the lowercase strings; "WARNING" is not one of them.
        $this->expectException(LogicException::class);

        new LogLevels(verificationFailed: 'WARNING');
    }
}
