<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key\Internal;

use Medzuch\Jwt\Exception\InvalidKeyException;
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

    public function testOctetStringEncodes(): void
    {
        self::assertSame("\x04\x03\x01\x02\x03", Asn1::octetString("\x01\x02\x03"));
        self::assertSame("\x04\x00", Asn1::octetString(''));
    }

    public function testBitStringPrependsUnusedBitsByte(): void
    {
        // BIT STRING tag (0x03), length 4 (3 payload + 1 unused-bits byte),
        // unused-bits 0x00, then 3 payload bytes.
        self::assertSame("\x03\x04\x00\x0A\x0B\x0C", Asn1::bitString("\x0A\x0B\x0C"));
    }

    /**
     * @param non-empty-string $dotted
     */
    #[DataProvider('oidProvider')]
    public function testOidEncoding(string $dotted, string $expectedHex): void
    {
        self::assertSame($expectedHex, bin2hex(Asn1::oid($dotted)));
    }

    /** @return iterable<string, array{non-empty-string, string}> */
    public static function oidProvider(): iterable
    {
        // X.690 §8.19 worked examples.
        yield 'id-ecPublicKey' => ['1.2.840.10045.2.1', '06072a8648ce3d0201'];
        yield 'prime256v1' => ['1.2.840.10045.3.1.7', '06082a8648ce3d030107'];
        yield 'secp384r1' => ['1.3.132.0.34', '06052b81040022'];
        yield 'secp521r1' => ['1.3.132.0.35', '06052b81040023'];
        yield 'zero arc inside' => ['1.2.0.3', '06032a0003'];
    }

    public function testOidRejectsSingleArc(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('at least two arcs');

        Asn1::oid('1');
    }

    public function testOidRejectsNonNumericArc(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('is not a non-negative integer');

        Asn1::oid('1.x.3');
    }

    public function testOidRejectsOutOfRangeFirstArc(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('first/second arc out of range');

        Asn1::oid('3.0');
    }

    public function testOidRejectsOutOfRangeSecondArc(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('first/second arc out of range');

        Asn1::oid('1.40');
    }

    public function testContextTaggedZeroPrependsExpectedTag(): void
    {
        // [0] EXPLICIT context-specific constructed tag = 0xA0.
        self::assertSame("\xA0\x03\x06\x01\x2A", Asn1::contextTagged(0, "\x06\x01\x2A"));
    }

    public function testContextTaggedOnePrependsExpectedTag(): void
    {
        self::assertSame("\xA1\x02\x00\x01", Asn1::contextTagged(1, "\x00\x01"));
    }

    public function testContextTaggedRejectsOutOfRangeTag(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Context tag 31 out of supported range');

        Asn1::contextTagged(31, '');
    }

    public function testEcdsaDerRoundTrip(): void
    {
        // Realistic ECDSA P-256 signature components.
        $r = str_pad("\x01\x23\x45", 32, "\x00", STR_PAD_LEFT);
        $s = str_pad("\xFE\xDC\xBA", 32, "\x00", STR_PAD_LEFT);
        $raw = $r . $s;

        $der = Asn1::ecdsaRawToDer($raw, 32);
        self::assertSame("\x30", $der[0], 'DER should start with SEQUENCE tag');

        self::assertSame(bin2hex($raw), bin2hex(Asn1::ecdsaDerToRaw($der, 32)));
    }

    public function testEcdsaDerToRawAcceptsOpensslOutput(): void
    {
        // Generate a real DER signature via OpenSSL and confirm we can parse it.
        $priv = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($priv);
        $der = '';
        self::assertTrue(openssl_sign('payload', $der, $priv, OPENSSL_ALGO_SHA256));

        $raw = Asn1::ecdsaDerToRaw($der, 32);
        self::assertSame(64, strlen($raw));
    }

    public function testEcdsaDerToRawRejectsTrailingBytes(): void
    {
        $der = Asn1::ecdsaRawToDer(str_repeat("\x01", 64), 32) . "\x00";

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Trailing bytes after ECDSA DER SEQUENCE');

        Asn1::ecdsaDerToRaw($der, 32);
    }

    public function testEcdsaDerToRawRejectsTrailingBytesInsideSequence(): void
    {
        $r = Asn1::integer(str_repeat("\x01", 32));
        $s = Asn1::integer(str_repeat("\x02", 32));
        $der = Asn1::sequence($r . $s . "\x05\x00"); // NULL trailer

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Trailing bytes inside ECDSA DER SEQUENCE');

        Asn1::ecdsaDerToRaw($der, 32);
    }

    public function testEcdsaDerToRawRejectsWrongOuterTag(): void
    {
        // OCTET STRING instead of SEQUENCE.
        $body = Asn1::integer(str_repeat("\x01", 32)) . Asn1::integer(str_repeat("\x02", 32));
        $der = Asn1::octetString($body);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('expected tag 0x30');

        Asn1::ecdsaDerToRaw($der, 32);
    }

    public function testEcdsaDerToRawRejectsEmptyInteger(): void
    {
        // SEQUENCE { INTEGER (empty), INTEGER 1 }
        $der = "\x30\x05\x02\x00\x02\x01\x01";

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('INTEGER body is empty');

        Asn1::ecdsaDerToRaw($der, 32);
    }

    public function testEcdsaDerToRawRejectsNegativeInteger(): void
    {
        // SEQUENCE { INTEGER 0xFF (high bit set, no padding), INTEGER 1 }
        $der = "\x30\x06\x02\x01\xFF\x02\x01\x01";

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('negative INTEGER');

        Asn1::ecdsaDerToRaw($der, 32);
    }

    public function testEcdsaDerToRawRejectsOversizedComponent(): void
    {
        // Build a DER signature whose r is 33 bytes (longer than P-256 coord).
        $r = str_pad("\xFF", 33, "\x01");
        $der = Asn1::sequence(Asn1::integer($r) . Asn1::integer(str_repeat("\x01", 32)));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('exceeds curve coord size');

        Asn1::ecdsaDerToRaw($der, 32);
    }

    public function testEcdsaDerToRawRejectsUnexpectedEofOnLength(): void
    {
        // SEQUENCE tag with no length byte.
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('expected length');

        Asn1::ecdsaDerToRaw("\x30", 32);
    }

    public function testEcdsaDerToRawRejectsTruncatedBody(): void
    {
        // SEQUENCE claiming 70 bytes but providing 2.
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('declared length exceeds buffer');

        Asn1::ecdsaDerToRaw("\x30\x46\x02\x01", 32);
    }

    public function testEcdsaDerToRawRejectsOverlongLengthEncoding(): void
    {
        // SEQUENCE with length byte 0x85 (5 length bytes, > our 4-byte cap).
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('unsupported length encoding');

        Asn1::ecdsaDerToRaw("\x30\x85", 32);
    }

    public function testEcdsaDerToRawRejectsNonCanonicalLongFormLengthBelow128(): void
    {
        // X.690 §10.1 — long form must not be used when short form would do.
        // SEQUENCE with `81 05 ...` (long form for length 5) instead of `05 ...`.
        $body = "\x02\x01\x01\x02\x01\x01"; // INTEGER 1, INTEGER 1
        $der = "\x30\x81\x06" . $body;

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('non-canonical length (long-form used for value < 128)');

        Asn1::ecdsaDerToRaw($der, 32);
    }

    public function testEcdsaDerToRawRejectsNonCanonicalLongFormLengthLeadingZero(): void
    {
        // X.690 §10.1 — long-form length octets must not have a leading 0x00.
        // SEQUENCE with `82 00 C8 ...` instead of `81 C8 ...` (length 200).
        $body = str_repeat("\x00", 200);
        $der = "\x30\x82\x00\xC8" . $body;

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('non-canonical length (long-form has leading 0x00 octet)');

        Asn1::ecdsaDerToRaw($der, 32);
    }

    public function testEcdsaDerToRawRejectsNonCanonicalIntegerRedundantLeadingZero(): void
    {
        // X.690 §10.4 — DER INTEGER uses minimum octets; leading 0x00 is
        // only allowed when the next byte has high bit set. `00 7F` is
        // redundant because `7F` already has high bit clear.
        $r = "\x02\x02\x00\x7F";                            // INTEGER 0x00 0x7F (non-canonical)
        $s = "\x02\x20" . str_repeat("\x01", 32);           // INTEGER ...01...
        $der = "\x30" . chr(strlen($r . $s)) . $r . $s;

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('non-canonical INTEGER (redundant leading 0x00 byte)');

        Asn1::ecdsaDerToRaw($der, 32);
    }

    public function testEcdsaDerToRawAcceptsLeadingZeroWhenNextByteHasHighBitSet(): void
    {
        // Canonical case: `00 80` is the correct DER encoding of the value
        // 0x80 (single-byte 0x80 would be interpreted as negative).
        $r = "\x02\x02\x00\x80";
        $s = "\x02\x02\x00\x80";
        $der = "\x30" . chr(strlen($r . $s)) . $r . $s;

        $raw = Asn1::ecdsaDerToRaw($der, 32);

        // r and s each decode to a single 0x80 byte, left-padded to 32.
        $expected = str_repeat("\x00", 31) . "\x80" . str_repeat("\x00", 31) . "\x80";
        self::assertSame(bin2hex($expected), bin2hex($raw));
    }

    public function testEcdsaDerToRawRejectsLengthBytesPastBuffer(): void
    {
        // SEQUENCE with length byte 0x82 (2 length bytes), only 1 follows.
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('length bytes extend past buffer');

        Asn1::ecdsaDerToRaw("\x30\x82\x01", 32);
    }

    public function testEcdsaRawToDerRejectsWrongLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('ECDSA raw signature must be 64 bytes');

        Asn1::ecdsaRawToDer(str_repeat("\x01", 63), 32);
    }

    private static function fromHex(string $hex): string
    {
        $bytes = hex2bin(str_replace(' ', '', $hex));
        self::assertNotFalse($bytes, 'invalid hex literal: ' . $hex);

        return $bytes;
    }
}
