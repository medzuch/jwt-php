<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\Signing\Internal;

use Medzuch\Jwt\Algorithm\Signing\Internal\Pss;
use Medzuch\Jwt\Exception\InvalidKeyException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Pss::class)]
final class PssTest extends TestCase
{
    /** @return iterable<string, array{string, int, int}> */
    public static function hashAndModBits(): iterable
    {
        // hashAlgo, modBits, hLen
        yield 'sha256/2048' => ['sha256', 2048, 32];
        yield 'sha384/2048' => ['sha384', 2048, 48];
        yield 'sha512/2048' => ['sha512', 2048, 64];
        yield 'sha256/3072' => ['sha256', 3072, 32];
        yield 'sha512/4096' => ['sha512', 4096, 64];
    }

    #[DataProvider('hashAndModBits')]
    public function testEncodeVerifyRoundTrip(string $hashAlgo, int $modBits, int $hLen): void
    {
        $emBits = $modBits - 1;
        $message = 'round-trip message ' . $hashAlgo;

        $em = Pss::encode($message, $hashAlgo, $emBits, $hLen);

        self::assertSame(intdiv($emBits + 7, 8), strlen($em));
        self::assertSame("\xbc", $em[strlen($em) - 1], 'EM trailer byte must be 0xbc');
        self::assertTrue(Pss::verify($message, $em, $hashAlgo, $emBits, $hLen));
    }

    public function testEncodeIsNonDeterministic(): void
    {
        // The salt is freshly random per encoding; two EMs for the same
        // message must differ. Both must verify.
        $a = Pss::encode('msg', 'sha256', 2047, 32);
        $b = Pss::encode('msg', 'sha256', 2047, 32);

        self::assertNotSame($a, $b);
        self::assertTrue(Pss::verify('msg', $a, 'sha256', 2047, 32));
        self::assertTrue(Pss::verify('msg', $b, 'sha256', 2047, 32));
    }

    public function testEncodeWithZeroSaltLengthIsDeterministic(): void
    {
        // sLen = 0 makes the encoding deterministic (no random material).
        $a = Pss::encode('msg', 'sha256', 2047, 0);
        $b = Pss::encode('msg', 'sha256', 2047, 0);

        self::assertSame($a, $b);
        self::assertTrue(Pss::verify('msg', $a, 'sha256', 2047, 0));
    }

    public function testVerifyRejectsWrongMessage(): void
    {
        $em = Pss::encode('orig', 'sha256', 2047, 32);

        self::assertFalse(Pss::verify('tampered', $em, 'sha256', 2047, 32));
    }

    public function testVerifyRejectsWrongLength(): void
    {
        $em = Pss::encode('msg', 'sha256', 2047, 32);

        self::assertFalse(Pss::verify('msg', $em . "\x00", 'sha256', 2047, 32));
        self::assertFalse(Pss::verify('msg', substr($em, 0, -1), 'sha256', 2047, 32));
    }

    public function testVerifyRejectsWrongTrailerByte(): void
    {
        $em = Pss::encode('msg', 'sha256', 2047, 32);
        $em[strlen($em) - 1] = "\x00";

        self::assertFalse(Pss::verify('msg', $em, 'sha256', 2047, 32));
    }

    public function testVerifyRejectsTopBitsSet(): void
    {
        // EM's leftmost bit must be zero (8*emLen - emBits = 1 for 2048-bit RSA).
        $em = Pss::encode('msg', 'sha256', 2047, 32);
        $em[0] = chr(ord($em[0]) | 0x80);

        self::assertFalse(Pss::verify('msg', $em, 'sha256', 2047, 32));
    }

    public function testVerifyRejectsWrongHValue(): void
    {
        $em = Pss::encode('msg', 'sha256', 2047, 32);
        // The H block is the 32 bytes immediately before the 0xbc trailer.
        $em[strlen($em) - 2] = chr(ord($em[strlen($em) - 2]) ^ 0x01);

        self::assertFalse(Pss::verify('msg', $em, 'sha256', 2047, 32));
    }

    public function testVerifyRejectsTamperedMaskedDb(): void
    {
        // Flip a byte in the middle of maskedDB; salt will decode wrong, H' won't match.
        $em = Pss::encode('msg', 'sha256', 2047, 32);
        $mid = intdiv(strlen($em), 4);
        $em[$mid] = chr(ord($em[$mid]) ^ 0xFF);

        self::assertFalse(Pss::verify('msg', $em, 'sha256', 2047, 32));
    }

    public function testVerifyRejectsBadDbDelimiter(): void
    {
        // After XORing dbMask out, byte at index (emLen - sLen - hLen - 2)
        // must be 0x01. Build an EM whose DB[psLen] is something else.
        $hashAlgo = 'sha256';
        $emBits = 2047;
        $emLen = 256;
        $hLen = 32;
        $sLen = 32;
        $psLen = $emLen - $sLen - $hLen - 2;

        $message = 'msg';
        $mHash = hash($hashAlgo, $message, true);
        $salt = str_repeat("\x42", $sLen);
        $mPrime = str_repeat("\x00", 8) . $mHash . $salt;
        $h = hash($hashAlgo, $mPrime, true);

        // Build DB with a *wrong* delimiter byte.
        $db = str_repeat("\x00", $psLen) . "\x02" . $salt; // 0x02 instead of 0x01
        $dbMask = Pss::mgf1($h, $emLen - $hLen - 1, $hashAlgo);
        $maskedDb = $db ^ $dbMask;
        $maskedDb[0] = chr(ord($maskedDb[0]) & 0x7F);
        $em = $maskedDb . $h . "\xbc";

        self::assertFalse(Pss::verify($message, $em, $hashAlgo, $emBits, $sLen));
    }

    public function testVerifyRejectsNonZeroPsPadding(): void
    {
        // Same construction as above, but with a non-zero byte in the PS block.
        $hashAlgo = 'sha256';
        $emBits = 2047;
        $emLen = 256;
        $hLen = 32;
        $sLen = 32;
        $psLen = $emLen - $sLen - $hLen - 2;

        $message = 'msg';
        $mHash = hash($hashAlgo, $message, true);
        $salt = str_repeat("\x42", $sLen);
        $mPrime = str_repeat("\x00", 8) . $mHash . $salt;
        $h = hash($hashAlgo, $mPrime, true);

        $db = str_repeat("\x00", $psLen - 1) . "\xFF" . "\x01" . $salt; // 0xFF where 0x00 should be
        $dbMask = Pss::mgf1($h, $emLen - $hLen - 1, $hashAlgo);
        $maskedDb = $db ^ $dbMask;
        $maskedDb[0] = chr(ord($maskedDb[0]) & 0x7F);
        $em = $maskedDb . $h . "\xbc";

        self::assertFalse(Pss::verify($message, $em, $hashAlgo, $emBits, $sLen));
    }

    public function testMgf1ProducesExactRequestedLength(): void
    {
        foreach ([1, 31, 32, 33, 64, 200, 999] as $maskLen) {
            $mask = Pss::mgf1('seed', $maskLen, 'sha256');
            self::assertSame($maskLen, strlen($mask), sprintf('maskLen=%d', $maskLen));
        }
    }

    public function testMgf1IsDeterministic(): void
    {
        self::assertSame(
            bin2hex(Pss::mgf1('seed', 100, 'sha256')),
            bin2hex(Pss::mgf1('seed', 100, 'sha256')),
        );
    }

    public function testMgf1MatchesFirstHashBlock(): void
    {
        // First hLen bytes of MGF1(seed, hLen) == Hash(seed || 0x00000000).
        $hash = hash('sha256', 'seed' . "\x00\x00\x00\x00", true);

        self::assertSame(bin2hex($hash), bin2hex(Pss::mgf1('seed', 32, 'sha256')));
    }

    public function testHashLengthRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('PSS: unsupported hash algorithm "md5"');

        Pss::encode('msg', 'md5', 2047, 16);
    }
}
