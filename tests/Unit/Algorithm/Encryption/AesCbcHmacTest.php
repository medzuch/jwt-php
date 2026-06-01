<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\Encryption;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\Encryption\A128CbcHs256;
use Medzuch\Jwt\Algorithm\Encryption\A192CbcHs384;
use Medzuch\Jwt\Algorithm\Encryption\A256CbcHs512;
use Medzuch\Jwt\Algorithm\Encryption\AesCbcHmac;
use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Primitives\ConstantTime;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AesCbcHmac::class)]
#[CoversClass(A128CbcHs256::class)]
#[CoversClass(A192CbcHs384::class)]
#[CoversClass(A256CbcHs512::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(ConstantTime::class)]
final class AesCbcHmacTest extends TestCase
{
    /** @return iterable<string, array{ContentEncryptionAlgorithm, string, positive-int}> */
    public static function algProvider(): iterable
    {
        yield 'A128CBC-HS256' => [new A128CbcHs256(), 'A128CBC-HS256', 32];
        yield 'A192CBC-HS384' => [new A192CbcHs384(), 'A192CBC-HS384', 48];
        yield 'A256CBC-HS512' => [new A256CbcHs512(), 'A256CBC-HS512', 64];
    }

    #[DataProvider('algProvider')]
    public function testMetadata(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        self::assertSame($name, $alg->name());
        self::assertSame($cekBytes, $alg->cekByteLength());
        self::assertSame(16, $alg->ivByteLength());
        self::assertSame(AlgorithmFamily::AesCbcHmac, $alg->family());
    }

    #[DataProvider('algProvider')]
    public function testRoundTrip(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        $iv = random_bytes(16);
        $plaintext = 'the quick brown fox jumps over the lazy dog';
        $aad = 'protected-header-bytes';

        [$ciphertext, $tag] = $alg->encrypt($plaintext, $cek, $iv, $aad);

        // Tag is the MAC truncated to the MAC-key length (half the CEK).
        self::assertSame($cekBytes / 2, strlen($tag));
        self::assertSame($plaintext, $alg->decrypt($ciphertext, $cek, $iv, $tag, $aad));
    }

    #[DataProvider('algProvider')]
    public function testEmptyPlaintextRoundTrips(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        $iv = random_bytes(16);

        [$ciphertext, $tag] = $alg->encrypt('', $cek, $iv, 'aad');

        // CBC pads, so an empty plaintext still yields one block of ciphertext.
        self::assertSame(16, strlen($ciphertext));
        self::assertSame('', $alg->decrypt($ciphertext, $cek, $iv, $tag, 'aad'));
    }

    #[DataProvider('algProvider')]
    public function testTamperedCiphertextIsRejected(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        $iv = random_bytes(16);
        [$ciphertext, $tag] = $alg->encrypt('secret payload here', $cek, $iv, 'aad');

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/tag mismatch/');
        $alg->decrypt(self::flipFirstByte($ciphertext), $cek, $iv, $tag, 'aad');
    }

    #[DataProvider('algProvider')]
    public function testTamperedAadIsRejected(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        $iv = random_bytes(16);
        [$ciphertext, $tag] = $alg->encrypt('secret payload here', $cek, $iv, 'aad');

        $this->expectException(DecryptionException::class);
        $alg->decrypt($ciphertext, $cek, $iv, $tag, 'AAD');
    }

    #[DataProvider('algProvider')]
    public function testTamperedTagIsRejected(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        $iv = random_bytes(16);
        [$ciphertext, $tag] = $alg->encrypt('secret payload here', $cek, $iv, 'aad');

        $this->expectException(DecryptionException::class);
        $alg->decrypt($ciphertext, $cek, $iv, self::flipFirstByte($tag), 'aad');
    }

    #[DataProvider('algProvider')]
    public function testWrongIvLengthIsRejectedOnEncrypt(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/IV/');

        $alg->encrypt('p', random_bytes($alg->cekByteLength()), random_bytes(12), 'aad');
    }

    #[DataProvider('algProvider')]
    public function testWrongIvLengthIsRejectedOnDecrypt(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        [$ciphertext, $tag] = $alg->encrypt('p', $cek, random_bytes(16), 'aad');

        // The IV-length guard must fire on decrypt before any MAC work, so the
        // error names the IV rather than reporting a tag mismatch.
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/IV/');

        $alg->decrypt($ciphertext, $cek, random_bytes(12), $tag, 'aad');
    }

    /**
     * RFC 7518 §B.1 known-answer vector — pins the exact ciphertext and tag so
     * mutations to the key split, the `AAD || IV || ciphertext || AL` MAC
     * input, or the AL length encoding are caught (a round-trip alone would
     * not notice a change applied symmetrically to encrypt and decrypt).
     */
    public function testReproducesRfc7518B1KnownAnswer(): void
    {
        $key = self::hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
        $iv = self::hex('1af38c2dc2b96ffdd86694092341bc04');
        $plaintext = 'A cipher system must not be required to be secret, and it '
            . 'must be able to fall into the hands of the enemy without inconvenience';
        $aad = 'The second principle of Auguste Kerckhoffs';
        $expectedCiphertext = self::hex(
            'c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9'
            . 'a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c7032336'
            . '09d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b'
            . '384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade5'
            . '4b8851ffb598f7f80074b9473c82e2db',
        );
        $expectedTag = self::hex('652c3fa36b0a7c5b3219fab3a30bc1c4');

        [$ciphertext, $tag] = (new A128CbcHs256())->encrypt($plaintext, $key, $iv, $aad);

        self::assertSame($expectedCiphertext, $ciphertext);
        self::assertSame($expectedTag, $tag);
    }

    private static function hex(string $hex): string
    {
        return (string) hex2bin($hex);
    }

    /** Flip the low bit of the first byte, preserving length. */
    private static function flipFirstByte(string $s): string
    {
        $s[0] = chr(ord($s[0]) ^ 0x01);

        return $s;
    }
}
