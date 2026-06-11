<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jws;

use LogicException;
use Medzuch\Jwt\Jws\ParsedJsonJws;
use Medzuch\Jwt\Jws\ParsedJws;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The aggregate parse view of a JWS JSON Serialization. The round-trip
 * behaviour lives in {@see JsonSerializerTest}; this pins down the
 * {@see ParsedJsonJws::single()} convenience on its own.
 */
#[CoversClass(ParsedJsonJws::class)]
#[UsesClass(ParsedJws::class)]
final class ParsedJsonJwsTest extends TestCase
{
    public function testSingleReturnsTheSoleSignature(): void
    {
        $sig = self::sig('a');
        $parsed = new ParsedJsonJws('payload', [$sig]);

        self::assertSame($sig, $parsed->single());
        self::assertSame('payload', $parsed->payload);
    }

    public function testSingleThrowsWhenMoreThanOneSignature(): void
    {
        $parsed = new ParsedJsonJws('payload', [self::sig('a'), self::sig('b')]);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('called on a JWS with 2 signatures');

        $parsed->single();
    }

    private static function sig(string $signature): ParsedJws
    {
        return new ParsedJws('aGVhZGVy', 'cGF5bG9hZA', 'c2ln', ['alg' => 'HS256'], 'payload', $signature);
    }
}
