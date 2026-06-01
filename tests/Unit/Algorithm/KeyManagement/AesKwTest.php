<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\KeyManagement;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Encryption\A128CbcHs256;
use Medzuch\Jwt\Algorithm\Encryption\A128Gcm;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A128Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\A192Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\AesKw;
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

#[CoversClass(AesKw::class)]
#[CoversClass(A128Kw::class)]
#[CoversClass(A192Kw::class)]
#[CoversClass(A256Kw::class)]
#[CoversClass(\Medzuch\Jwt\Algorithm\KeyManagement\Internal\AesKeyWrap::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(KeyManagementMode::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\CekEncryptionResult::class)]
#[UsesClass(A128CbcHs256::class)]
#[UsesClass(A128Gcm::class)]
#[UsesClass(A256Gcm::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Encryption\AesCbcHmac::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Encryption\AesGcm::class)]
#[UsesClass(OctKey::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\Key::class)]
#[UsesClass(\Medzuch\Jwt\Key\SymmetricKey::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Random::class)]
#[UsesClass(Base64Url::class)]
final class AesKwTest extends TestCase
{
    /** @return iterable<string, array{AesKw, string, positive-int}> */
    public static function algProvider(): iterable
    {
        yield 'A128KW' => [new A128Kw(), 'A128KW', 16];
        yield 'A192KW' => [new A192Kw(), 'A192KW', 24];
        yield 'A256KW' => [new A256Kw(), 'A256KW', 32];
    }

    #[DataProvider('algProvider')]
    public function testMetadata(AesKw $alg, string $name, int $kekBytes): void
    {
        self::assertGreaterThan(0, $kekBytes);
        self::assertSame($name, $alg->name());
        self::assertSame(AlgorithmFamily::AesKw, $alg->family());
        self::assertSame(KeyManagementMode::KeyWrapping, $alg->mode());
    }

    #[DataProvider('algProvider')]
    public function testWrapsAFreshRandomCekAndUnwrapsIt(AesKw $alg, string $name, int $kekBytes): void
    {
        $kek = OctKey::fromBinary(random_bytes(max(1, $kekBytes)), $name, kid: 'k1');
        $enc = new A256Gcm();

        $first = $alg->encryptKey($kek, $enc);
        $second = $alg->encryptKey($kek, $enc);

        // Fresh CEK per call (not a shared key, unlike `dir`).
        self::assertSame($enc->cekByteLength(), strlen($first->cek));
        self::assertNotSame($first->cek, $second->cek);
        self::assertNotSame('', $first->encryptedKey);
        self::assertSame([], $first->headerParameters);

        self::assertSame($first->cek, $alg->decryptKey($kek, $enc, $first->encryptedKey, []));
    }

    /**
     * RFC 7516 §A.3 known-answer: unwrapping the published JWE Encrypted Key
     * with the §A.3 shared key must recover the §A.3 Content Encryption Key.
     * Because we decrypt *externally produced* wrap bytes, this pins the
     * cipher name and the RFC 3394 default IV — a mutation to either breaks the
     * integrity check and the unwrap fails.
     */
    public function testUnwrapReproducesRfc7516A3ContentEncryptionKey(): void
    {
        // §A.3.3 shared symmetric key {"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}.
        $kek = OctKey::fromBinary(Base64Url::decode('GawgguFyGrWKav7AX4VKUg'), 'A128KW', kid: 'a3');
        // §A.3.3 JWE Encrypted Key.
        $encryptedKey = Base64Url::decode('6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ');
        // §A.3.2 256-bit CEK.
        $expectedCek = self::bytes(
            4,
            211,
            31,
            197,
            84,
            157,
            252,
            254,
            11,
            100,
            157,
            250,
            63,
            170,
            106,
            206,
            107,
            124,
            212,
            45,
            111,
            107,
            9,
            219,
            200,
            177,
            0,
            240,
            143,
            156,
            44,
            207,
        );

        $cek = (new A128Kw())->decryptKey($kek, new A128CbcHs256(), $encryptedKey, []);

        self::assertSame($expectedCek, $cek);
    }

    public function testRejectsNonOctKey(): void
    {
        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/A128KW requires an OctKey/');

        (new A128Kw())->encryptKey(HmacKey::fromBinary(random_bytes(32), 'HS256'), new A256Gcm());
    }

    public function testRejectsKekBoundToDifferentAlgorithm(): void
    {
        // A KEK bound to A256KW cannot wrap under A128KW (one key, one alg).
        $kek = OctKey::fromBinary(random_bytes(32), 'A256KW', kid: 'k1');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/A256KW.*A128KW|cannot be used/');

        (new A128Kw())->encryptKey($kek, new A256Gcm());
    }

    public function testEnforcesKeyOpsOnWrap(): void
    {
        $kek = OctKey::fromBinary(random_bytes(16), 'A128KW', keyOps: ['unwrapKey'], kid: 'kek-7');

        $this->expectException(KeyMismatchException::class);
        // The message names the offending key by its kid, not the "(no kid)"
        // fallback.
        $this->expectExceptionMessageMatches('/Key kek-7 does not permit operation "wrapKey"/');

        (new A128Kw())->encryptKey($kek, new A256Gcm());
    }

    public function testEnforcesKeyOpsOnUnwrap(): void
    {
        $kek = OctKey::fromBinary(random_bytes(16), 'A128KW', keyOps: ['wrapKey']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/does not permit operation "unwrapKey"/');

        (new A128Kw())->decryptKey($kek, new A256Gcm(), random_bytes(40), []);
    }

    public function testUnwrapRejectsTamperedEncryptedKey(): void
    {
        $kek = OctKey::fromBinary(random_bytes(16), 'A128KW', kid: 'k1');
        $wrapped = (new A128Kw())->encryptKey($kek, new A256Gcm())->encryptedKey;

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/unwrap failed/');

        (new A128Kw())->decryptKey($kek, new A256Gcm(), self::flipFirstByte($wrapped), []);
    }

    public function testUnwrapRejectsWrongKek(): void
    {
        $kek = OctKey::fromBinary(random_bytes(16), 'A128KW', kid: 'k1');
        $wrapped = (new A128Kw())->encryptKey($kek, new A256Gcm())->encryptedKey;
        $otherKek = OctKey::fromBinary(random_bytes(16), 'A128KW', kid: 'k2');

        $this->expectException(DecryptionException::class);

        (new A128Kw())->decryptKey($otherKek, new A256Gcm(), $wrapped, []);
    }

    /** @no-named-arguments */
    private static function bytes(int ...$octets): string
    {
        return implode('', array_map('chr', $octets));
    }

    private static function flipFirstByte(string $s): string
    {
        $s[0] = chr(ord($s[0]) ^ 0x01);

        return $s;
    }
}
