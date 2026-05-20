<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Primitives;

use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Primitives\Utf8;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Utf8::class)]
final class Utf8Test extends TestCase
{
    #[DataProvider('validProvider')]
    public function testAcceptsWellFormedUtf8(string $bytes): void
    {
        self::assertTrue(Utf8::isValid($bytes));
    }

    /** @return iterable<string, array{string}> */
    public static function validProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'ascii' => ['hello'];
        yield 'two-byte sequence' => ["\xC3\xA9"];           // é
        yield 'three-byte sequence' => ["\xE2\x82\xAC"];      // €
        yield 'four-byte sequence' => ["\xF0\x9F\x98\x80"];   // 😀
        yield 'json header bytes' => ['{"alg":"HS256","typ":"JWT"}'];
    }

    #[DataProvider('invalidProvider')]
    public function testRejectsIllFormedOrAmbiguousInput(string $bytes): void
    {
        self::assertFalse(Utf8::isValid($bytes));
    }

    /** @return iterable<string, array{string}> */
    public static function invalidProvider(): iterable
    {
        yield 'utf-8 BOM' => ["\xEF\xBB\xBF" . 'payload'];
        yield 'utf-16 BE BOM' => ["\xFE\xFF" . 'payload'];
        yield 'utf-16 LE BOM' => ["\xFF\xFE" . 'payload'];
        yield 'lone continuation byte' => ["\x80"];
        yield 'truncated 2-byte sequence' => ["\xC3"];
        yield 'overlong slash (C0 AF)' => ["\xC0\xAF"];
        yield 'overlong NUL (C0 80)' => ["\xC0\x80"];
        yield 'high surrogate U+D800' => ["\xED\xA0\x80"];
        yield 'low surrogate U+DFFF' => ["\xED\xBF\xBF"];
        yield 'invalid lead byte 0xFE' => ["\xFE"];
        yield 'invalid lead byte 0xFF' => ["\xFF"];
    }

    public function testAssertValidIsSilentOnGoodInput(): void
    {
        $this->expectNotToPerformAssertions();

        Utf8::assertValid('plain ascii');
    }

    public function testAssertValidThrowsOnBom(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/UTF-8/');

        Utf8::assertValid("\xEF\xBB\xBF" . 'whatever');
    }

    public function testAssertValidThrowsOnIllFormed(): void
    {
        $this->expectException(MalformedJwtException::class);

        Utf8::assertValid("\xC0\x80"); // overlong NUL
    }
}
