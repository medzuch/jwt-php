<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\KeyManagement\Internal;

use Medzuch\Jwt\Algorithm\KeyManagement\Internal\ConcatKdf;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ConcatKdf::class)]
#[UsesClass(Base64Url::class)]
final class ConcatKdfTest extends TestCase
{
    /**
     * RFC 7518 Appendix C known-answer (single SHA-256 round): the published
     * Z, AlgorithmID "A128GCM", apu "Alice", apv "Bob", and keydatalen 128
     * must derive the published 128-bit key. This pins the OtherInfo layout —
     * the 32-bit length prefixes, the order, and the trailing keydatalen — and
     * the truncation, byte-for-byte.
     */
    public function testReproducesRfc7518AppendixC(): void
    {
        $z = self::bytes(
            158,
            86,
            217,
            29,
            129,
            113,
            53,
            211,
            114,
            131,
            66,
            131,
            191,
            132,
            38,
            156,
            251,
            49,
            110,
            163,
            218,
            128,
            106,
            72,
            246,
            218,
            167,
            121,
            140,
            254,
            144,
            196,
        );

        $derived = ConcatKdf::derive($z, 16, 'A128GCM', 'Alice', 'Bob');

        self::assertSame('VqqN6vgjbSBcIijNcacQGg', Base64Url::encode($derived));
    }

    /**
     * A 48-byte request needs two SHA-256 rounds. Recomputing the expected
     * material with an independent inline reference (distinct from
     * {@see ConcatKdf}) pins the round counter and the concatenation order —
     * mutations a same-code round-trip would never reveal.
     */
    public function testMultiRoundDerivationConcatenatesCounterRounds(): void
    {
        $z = random_bytes(32);
        $algId = 'A192CBC-HS384';
        $apu = 'party-u';
        $apv = 'party-v';
        $keyBytes = 48;

        $otherInfo = pack('N', strlen($algId)) . $algId
            . pack('N', strlen($apu)) . $apu
            . pack('N', strlen($apv)) . $apv
            . pack('N', $keyBytes * 8);
        $expected = substr(
            hash('sha256', pack('N', 1) . $z . $otherInfo, true)
            . hash('sha256', pack('N', 2) . $z . $otherInfo, true),
            0,
            $keyBytes,
        );

        $derived = ConcatKdf::derive($z, $keyBytes, $algId, $apu, $apv);

        self::assertSame(48, strlen($derived));
        self::assertSame($expected, $derived);
    }

    public function testEmptyPartyInfoIsTheDefault(): void
    {
        $z = random_bytes(32);

        // Explicit empty apu/apv equals the defaulted call.
        self::assertSame(
            ConcatKdf::derive($z, 16, 'A128GCM'),
            ConcatKdf::derive($z, 16, 'A128GCM', '', ''),
        );
    }

    /** @no-named-arguments */
    private static function bytes(int ...$octets): string
    {
        return implode('', array_map('chr', $octets));
    }
}
