<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key\Internal;

use Medzuch\Jwt\Key\Internal\Asn1;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Asn1::class)]
final class Asn1Test extends TestCase
{
    #[DataProvider('integerProvider')]
    public function testIntegerEncoding(string $inputHex, string $expectedDerHex): void
    {
        $input = self::fromHex($inputHex);
        $expected = self::fromHex($expectedDerHex);

        self::assertSame(
            bin2hex($expected),
            bin2hex(Asn1::integer($input)),
        );
    }

    /** @return iterable<string, array{string, string}> */
    public static function integerProvider(): iterable
    {
        // Tag 0x02 INTEGER, then length, then content.
        yield 'small positive' => ['01',          '020101'];        // length 1, value 0x01
        yield 'high bit set needs padding' => ['80', '02020080'];   // padded to keep it positive
        yield 'three-byte value' => ['010001',    '0203010001'];    // RSA public exponent F4
        yield 'leading null stripped' => ['000001', '020101'];      // leading 0x00 redundant
        yield 'all-null becomes zero' => ['000000', '020100'];      // collapses to single 0
    }

    public function testIntegerForLongValueUsesLongFormLength(): void
    {
        // 200-byte value triggers the long-form length encoding (length
        // byte 0x81 followed by the length value).
        $bytes = str_repeat("\x01", 200);
        $der = Asn1::integer($bytes);

        // Tag 0x02, then 0x81 (long form, 1 length byte), then 0xC8 (=200), then content.
        self::assertSame("\x02\x81\xC8", substr($der, 0, 3));
        self::assertSame(200, strlen($der) - 3);
    }

    public function testIntegerForVeryLongValueUsesTwoByteLength(): void
    {
        $bytes = str_repeat("\x01", 300);
        $der = Asn1::integer($bytes);

        // 0x02, 0x82 (long form, 2 length bytes), 0x01 0x2C (=300).
        self::assertSame("\x02\x82\x01\x2C", substr($der, 0, 4));
    }

    public function testSequenceWraps(): void
    {
        $contents = "\x02\x01\x01\x02\x01\x02"; // INTEGER 1, INTEGER 2
        $der = Asn1::sequence($contents);

        // Tag 0x30, length 6, then the two integers.
        self::assertSame("\x30\x06" . $contents, $der);
    }

    public function testToPemWrapsAndLabels(): void
    {
        $der = Asn1::sequence(Asn1::integer("\x01") . Asn1::integer("\x01\x00\x01"));
        $pem = Asn1::toPem($der, 'RSA PUBLIC KEY');

        self::assertStringStartsWith("-----BEGIN RSA PUBLIC KEY-----\n", $pem);
        self::assertStringEndsWith("-----END RSA PUBLIC KEY-----\n", $pem);
        // Base64 line length is 64 chars per RFC 7468 §3.
        $body = trim(substr($pem, 30, -28));
        foreach (explode("\n", $body) as $line) {
            self::assertLessThanOrEqual(64, strlen($line));
        }
    }

    private static function fromHex(string $hex): string
    {
        $bytes = hex2bin($hex);
        self::assertNotFalse($bytes, 'invalid hex literal: ' . $hex);

        return $bytes;
    }
}
