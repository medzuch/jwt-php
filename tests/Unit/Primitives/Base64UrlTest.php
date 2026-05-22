<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Primitives;

use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Base64Url::class)]
final class Base64UrlTest extends TestCase
{
    public function testEncodesEmptyStringToEmptyString(): void
    {
        self::assertSame('', Base64Url::encode(''));
    }

    public function testDecodesEmptyStringToEmptyString(): void
    {
        self::assertSame('', Base64Url::decode(''));
    }

    /**
     * RFC 7515 §A.1.1 — JOSE header octets and their base64url encoding.
     *
     * These bytes are the exact header from the RFC HS256 example; using
     * them here means the same fixture flows up into PR #6's conformance
     * test and stays consistent.
     */
    public function testEncodesRfc7515ExampleHeader(): void
    {
        $headerOctets = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";

        self::assertSame(
            'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
            Base64Url::encode($headerOctets),
        );
    }

    public function testDecodesRfc7515ExampleHeader(): void
    {
        $headerOctets = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";

        self::assertSame(
            $headerOctets,
            Base64Url::decode('eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'),
        );
    }

    #[DataProvider('roundTripProvider')]
    public function testRoundTripIsLossless(string $bytes): void
    {
        self::assertSame($bytes, Base64Url::decode(Base64Url::encode($bytes)));
    }

    /** @return iterable<string, array{string}> */
    public static function roundTripProvider(): iterable
    {
        yield 'single byte' => ["\x00"];
        yield 'two bytes' => ["\xff\xfe"];
        yield 'three bytes' => ['abc'];
        yield 'ascii sentence' => ['The quick brown fox jumps over the lazy dog.'];
        yield 'random binary' => ["\x00\x01\x02\xff\xfe\xfd\x80\x7f"];
        yield 'utf-8 multibyte' => ['héllo, wörld — αβγ'];
        yield 'high entropy bytes' => [hash('sha256', 'salt', binary: true)];
    }

    public function testEncodingHasNoPaddingCharacters(): void
    {
        // Two-byte input produces an encoding that would have "==" padding
        // in standard base64. In base64url-nopad form, no `=` may appear.
        $encoded = Base64Url::encode('ab');

        self::assertStringNotContainsString('=', $encoded);
    }

    public function testEncodingUsesUrlSafeAlphabet(): void
    {
        // 0xFB 0xFF -> standard base64 "+/" ; url-safe must use "-_".
        $encoded = Base64Url::encode("\xfb\xff");

        self::assertStringNotContainsString('+', $encoded);
        self::assertStringNotContainsString('/', $encoded);
    }

    #[DataProvider('malformedInputProvider')]
    public function testDecodeThrowsOnInvalidInput(string $input): void
    {
        try {
            Base64Url::decode($input);
            self::fail('expected MalformedJwtException');
        } catch (MalformedJwtException $e) {
            // Pin the literal `0` exception code against Increment/Decrement
            // mutants on the throw site.
            self::assertSame(0, $e->getCode());
            self::assertNotNull($e->getPrevious());
        }
    }

    /** @return iterable<string, array{string}> */
    public static function malformedInputProvider(): iterable
    {
        yield 'standard base64 plus sign' => ['ab+c'];
        yield 'standard base64 slash' => ['a/bc'];
        yield 'has padding' => ['YWI='];
        yield 'whitespace inside' => ['YW Jj'];
        yield 'null byte inside' => ["YW\x00Jj"];
    }
}
