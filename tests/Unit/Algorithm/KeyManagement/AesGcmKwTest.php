<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\KeyManagement;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A128GcmKw;
use Medzuch\Jwt\Algorithm\KeyManagement\A192GcmKw;
use Medzuch\Jwt\Algorithm\KeyManagement\A256GcmKw;
use Medzuch\Jwt\Algorithm\KeyManagement\AesGcmKw;
use Medzuch\Jwt\Algorithm\KeyManagementMode;
use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AesGcmKw::class)]
#[CoversClass(A128GcmKw::class)]
#[CoversClass(A192GcmKw::class)]
#[CoversClass(A256GcmKw::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(KeyManagementMode::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\CekEncryptionResult::class)]
#[UsesClass(A256Gcm::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Encryption\AesGcm::class)]
#[UsesClass(OctKey::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\Key::class)]
#[UsesClass(\Medzuch\Jwt\Key\SymmetricKey::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Random::class)]
#[UsesClass(Base64Url::class)]
final class AesGcmKwTest extends TestCase
{
    /** @return iterable<string, array{AesGcmKw, string, positive-int}> */
    public static function algProvider(): iterable
    {
        yield 'A128GCMKW' => [new A128GcmKw(), 'A128GCMKW', 16];
        yield 'A192GCMKW' => [new A192GcmKw(), 'A192GCMKW', 24];
        yield 'A256GCMKW' => [new A256GcmKw(), 'A256GCMKW', 32];
    }

    #[DataProvider('algProvider')]
    public function testMetadata(AesGcmKw $alg, string $name, int $kekBytes): void
    {
        self::assertGreaterThan(0, $kekBytes);
        self::assertSame($name, $alg->name());
        self::assertSame(AlgorithmFamily::AesGcmKw, $alg->family());
        self::assertSame(KeyManagementMode::KeyWrapping, $alg->mode());
    }

    #[DataProvider('algProvider')]
    public function testWrapsCekAndCarriesIvAndTagInHeader(AesGcmKw $alg, string $name, int $kekBytes): void
    {
        $kek = OctKey::fromBinary(random_bytes(max(1, $kekBytes)), $name, kid: 'k1');
        $enc = new A256Gcm();

        $result = $alg->encryptKey($kek, $enc);

        self::assertSame($enc->cekByteLength(), strlen($result->cek));
        self::assertNotSame('', $result->encryptedKey);
        self::assertSame(['iv', 'tag'], array_keys($result->headerParameters));

        // The per-recipient parameters pin the JOSE 96-bit IV / 128-bit tag.
        $iv = $result->headerParameters['iv'];
        $tag = $result->headerParameters['tag'];
        self::assertIsString($iv);
        self::assertIsString($tag);
        self::assertSame(12, strlen(Base64Url::decode($iv)));
        self::assertSame(16, strlen(Base64Url::decode($tag)));

        self::assertSame($result->cek, $alg->decryptKey($kek, $enc, $result->encryptedKey, $result->headerParameters));
    }

    #[DataProvider('algProvider')]
    public function testFreshIvPerWrap(AesGcmKw $alg, string $name, int $kekBytes): void
    {
        $kek = OctKey::fromBinary(random_bytes(max(1, $kekBytes)), $name, kid: 'k1');

        $a = $alg->encryptKey($kek, new A256Gcm());
        $b = $alg->encryptKey($kek, new A256Gcm());

        self::assertNotSame($a->headerParameters['iv'], $b->headerParameters['iv']);
    }

    public function testUnwrapRejectsTamperedEncryptedKey(): void
    {
        $kek = OctKey::fromBinary(random_bytes(32), 'A256GCMKW', kid: 'k1');
        $result = (new A256GcmKw())->encryptKey($kek, new A256Gcm());

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/unwrap failed/');

        (new A256GcmKw())->decryptKey($kek, new A256Gcm(), self::flipFirstByte($result->encryptedKey), $result->headerParameters);
    }

    public function testUnwrapRejectsTamperedTag(): void
    {
        $kek = OctKey::fromBinary(random_bytes(32), 'A256GCMKW', kid: 'k1');
        $result = (new A256GcmKw())->encryptKey($kek, new A256Gcm());
        $header = $result->headerParameters;
        self::assertIsString($header['tag']);
        $header['tag'] = Base64Url::encode(self::flipFirstByte(Base64Url::decode($header['tag'])));

        $this->expectException(DecryptionException::class);

        (new A256GcmKw())->decryptKey($kek, new A256Gcm(), $result->encryptedKey, $header);
    }

    public function testDecryptRejectsMissingIv(): void
    {
        $kek = OctKey::fromBinary(random_bytes(32), 'A256GCMKW', kid: 'k1');

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/missing the "iv"/');

        (new A256GcmKw())->decryptKey($kek, new A256Gcm(), random_bytes(32), ['tag' => Base64Url::encode(random_bytes(16))]);
    }

    public function testDecryptRejectsMissingTag(): void
    {
        $kek = OctKey::fromBinary(random_bytes(32), 'A256GCMKW', kid: 'k1');

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/missing the "tag"/');

        (new A256GcmKw())->decryptKey($kek, new A256Gcm(), random_bytes(32), ['iv' => Base64Url::encode(random_bytes(12))]);
    }

    public function testDecryptRejectsWrongLengthIv(): void
    {
        $kek = OctKey::fromBinary(random_bytes(32), 'A256GCMKW', kid: 'k1');

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/"iv" must be 12 bytes/');

        (new A256GcmKw())->decryptKey($kek, new A256Gcm(), random_bytes(32), [
            'iv' => Base64Url::encode(random_bytes(8)),
            'tag' => Base64Url::encode(random_bytes(16)),
        ]);
    }

    public function testDecryptRejectsWrongLengthTag(): void
    {
        $kek = OctKey::fromBinary(random_bytes(32), 'A256GCMKW', kid: 'k1');

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/"tag" must be 16 bytes/');

        (new A256GcmKw())->decryptKey($kek, new A256Gcm(), random_bytes(32), [
            'iv' => Base64Url::encode(random_bytes(12)),
            'tag' => Base64Url::encode(random_bytes(12)),
        ]);
    }

    public function testDecryptRejectsNonBase64UrlIv(): void
    {
        $kek = OctKey::fromBinary(random_bytes(32), 'A256GCMKW', kid: 'k1');

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/"iv" header parameter is not valid base64url/');

        (new A256GcmKw())->decryptKey($kek, new A256Gcm(), random_bytes(32), [
            'iv' => 'not valid base64url!!',
            'tag' => Base64Url::encode(random_bytes(16)),
        ]);
    }

    public function testRejectsNonOctKey(): void
    {
        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/A256GCMKW requires an OctKey/');

        (new A256GcmKw())->encryptKey(HmacKey::fromBinary(random_bytes(32), 'HS256'), new A256Gcm());
    }

    public function testRejectsKekBoundToDifferentAlgorithm(): void
    {
        $kek = OctKey::fromBinary(random_bytes(16), 'A128GCMKW', kid: 'k1');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/A128GCMKW.*A256GCMKW|cannot be used/');

        (new A256GcmKw())->encryptKey($kek, new A256Gcm());
    }

    public function testEnforcesKeyOpsOnWrap(): void
    {
        $kek = OctKey::fromBinary(random_bytes(32), 'A256GCMKW', keyOps: ['unwrapKey'], kid: 'kek-7');

        $this->expectException(KeyMismatchException::class);
        // The message names the offending key by its kid, not the "(no kid)"
        // fallback.
        $this->expectExceptionMessageMatches('/Key kek-7 does not permit operation "wrapKey"/');

        (new A256GcmKw())->encryptKey($kek, new A256Gcm());
    }

    private static function flipFirstByte(string $s): string
    {
        $s[0] = chr(ord($s[0]) ^ 0x01);

        return $s;
    }
}
