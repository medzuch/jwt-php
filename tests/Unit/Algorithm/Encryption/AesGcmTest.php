<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\Encryption;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\Encryption\A128Gcm;
use Medzuch\Jwt\Algorithm\Encryption\A192Gcm;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\Encryption\AesGcm;
use Medzuch\Jwt\Exception\DecryptionException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AesGcm::class)]
#[CoversClass(A128Gcm::class)]
#[CoversClass(A192Gcm::class)]
#[CoversClass(A256Gcm::class)]
#[UsesClass(AlgorithmFamily::class)]
final class AesGcmTest extends TestCase
{
    /** @return iterable<string, array{ContentEncryptionAlgorithm, string, positive-int}> */
    public static function algProvider(): iterable
    {
        yield 'A128GCM' => [new A128Gcm(), 'A128GCM', 16];
        yield 'A192GCM' => [new A192Gcm(), 'A192GCM', 24];
        yield 'A256GCM' => [new A256Gcm(), 'A256GCM', 32];
    }

    #[DataProvider('algProvider')]
    public function testMetadata(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        self::assertSame($name, $alg->name());
        self::assertSame($cekBytes, $alg->cekByteLength());
        self::assertSame(12, $alg->ivByteLength());
        self::assertSame(AlgorithmFamily::AesGcm, $alg->family());
    }

    #[DataProvider('algProvider')]
    public function testRoundTrip(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        $iv = random_bytes(12);
        $plaintext = 'the quick brown fox';
        $aad = 'protected-header-bytes';

        [$ciphertext, $tag] = $alg->encrypt($plaintext, $cek, $iv, $aad);

        self::assertSame(16, strlen($tag));
        self::assertSame(strlen($plaintext), strlen($ciphertext));
        self::assertSame($plaintext, $alg->decrypt($ciphertext, $cek, $iv, $tag, $aad));
    }

    #[DataProvider('algProvider')]
    public function testEmptyPlaintextRoundTrips(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        $iv = random_bytes(12);

        [$ciphertext, $tag] = $alg->encrypt('', $cek, $iv, 'aad');

        self::assertSame('', $ciphertext);
        self::assertSame('', $alg->decrypt($ciphertext, $cek, $iv, $tag, 'aad'));
    }

    #[DataProvider('algProvider')]
    public function testTamperedCiphertextIsRejected(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        $iv = random_bytes(12);
        [$ciphertext, $tag] = $alg->encrypt('secret payload', $cek, $iv, 'aad');

        $this->expectException(DecryptionException::class);
        $alg->decrypt(self::flipFirstByte($ciphertext), $cek, $iv, $tag, 'aad');
    }

    #[DataProvider('algProvider')]
    public function testTamperedTagIsRejected(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        $iv = random_bytes(12);
        [$ciphertext, $tag] = $alg->encrypt('secret payload', $cek, $iv, 'aad');

        $this->expectException(DecryptionException::class);
        $alg->decrypt($ciphertext, $cek, $iv, self::flipFirstByte($tag), 'aad');
    }

    #[DataProvider('algProvider')]
    public function testTamperedAadIsRejected(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        $iv = random_bytes(12);
        [$ciphertext, $tag] = $alg->encrypt('secret payload', $cek, $iv, 'aad');

        $this->expectException(DecryptionException::class);
        $alg->decrypt($ciphertext, $cek, $iv, $tag, 'AAD');
    }

    #[DataProvider('algProvider')]
    public function testWrongIvLengthIsRejectedOnEncrypt(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/IV/');

        $alg->encrypt('p', random_bytes($alg->cekByteLength()), random_bytes(11), 'aad');
    }

    #[DataProvider('algProvider')]
    public function testWrongIvLengthIsRejectedOnDecrypt(ContentEncryptionAlgorithm $alg, string $name, int $cekBytes): void
    {
        $cek = random_bytes($alg->cekByteLength());
        [$ciphertext, $tag] = $alg->encrypt('p', $cek, random_bytes(12), 'aad');

        // The IV-length guard must fire on decrypt, naming the IV rather than
        // surfacing a generic GCM authentication failure.
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/IV/');

        $alg->decrypt($ciphertext, $cek, random_bytes(11), $tag, 'aad');
    }

    /** Flip the low bit of the first byte, preserving length. */
    private static function flipFirstByte(string $s): string
    {
        $s[0] = chr(ord($s[0]) ^ 0x01);

        return $s;
    }
}
