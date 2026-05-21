<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwt;

use Medzuch\Jwt\Jwt\Header;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Header::class)]
final class HeaderTest extends TestCase
{
    public function testRegisteredAccessors(): void
    {
        $h = new Header(['alg' => 'HS256', 'typ' => 'at+jwt', 'kid' => 'k1', 'cty' => 'JWT', 'custom' => 'x']);

        self::assertSame('HS256', $h->algorithm());
        self::assertSame('at+jwt', $h->type());
        self::assertSame('k1', $h->keyId());
        self::assertSame('JWT', $h->contentType());
        self::assertSame('x', $h->get('custom'));
        self::assertTrue($h->has('custom'));
        self::assertFalse($h->has('missing'));
    }

    public function testOptionalsAreNullWhenAbsent(): void
    {
        $h = new Header(['alg' => 'HS256']);

        self::assertNull($h->type());
        self::assertNull($h->keyId());
        self::assertNull($h->contentType());
    }

    public function testAllReturnsRawArray(): void
    {
        $values = ['alg' => 'HS256', 'kid' => 'k1'];

        self::assertSame($values, (new Header($values))->all());
    }
}
