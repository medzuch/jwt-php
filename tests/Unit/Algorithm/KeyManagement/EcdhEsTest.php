<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\KeyManagement;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\Encryption\A128Gcm;
use Medzuch\Jwt\Algorithm\Encryption\A256CbcHs512;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEs;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEsA128Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEsA192Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEsA256Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEsAesKw;
use Medzuch\Jwt\Algorithm\KeyManagementMode;
use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(EcdhEs::class)]
#[CoversClass(EcdhEsAesKw::class)]
#[CoversClass(EcdhEsA128Kw::class)]
#[CoversClass(EcdhEsA192Kw::class)]
#[CoversClass(EcdhEsA256Kw::class)]
#[CoversClass(\Medzuch\Jwt\Algorithm\KeyManagement\Internal\EcdhKeyAgreement::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\Internal\ConcatKdf::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\Internal\AesKeyWrap::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(KeyManagementMode::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\CekEncryptionResult::class)]
#[UsesClass(A128Gcm::class)]
#[UsesClass(A256Gcm::class)]
#[UsesClass(A256CbcHs512::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Encryption\AesGcm::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Encryption\AesCbcHmac::class)]
#[UsesClass(EcPrivateKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\EcPublicKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\EcKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\Key::class)]
#[UsesClass(\Medzuch\Jwt\Key\AsymmetricKey::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\SymmetricKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\Internal\EcCurve::class)]
#[UsesClass(\Medzuch\Jwt\Key\Internal\Asn1::class)]
#[UsesClass(\Medzuch\Jwt\Key\Internal\JwkAttributes::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Random::class)]
final class EcdhEsTest extends TestCase
{
    public function testDirectMetadata(): void
    {
        $alg = new EcdhEs();

        self::assertSame('ECDH-ES', $alg->name());
        self::assertSame(AlgorithmFamily::EcdhEs, $alg->family());
        self::assertSame(KeyManagementMode::DirectKeyAgreement, $alg->mode());
    }

    /** @return iterable<string, array{EcdhEsAesKw, string, KeyManagementMode}> */
    public static function kwProvider(): iterable
    {
        yield 'ECDH-ES+A128KW' => [new EcdhEsA128Kw(), 'ECDH-ES+A128KW', KeyManagementMode::KeyAgreementWithKeyWrapping];
        yield 'ECDH-ES+A192KW' => [new EcdhEsA192Kw(), 'ECDH-ES+A192KW', KeyManagementMode::KeyAgreementWithKeyWrapping];
        yield 'ECDH-ES+A256KW' => [new EcdhEsA256Kw(), 'ECDH-ES+A256KW', KeyManagementMode::KeyAgreementWithKeyWrapping];
    }

    #[DataProvider('kwProvider')]
    public function testKeyWrappingMetadata(EcdhEsAesKw $alg, string $name, KeyManagementMode $mode): void
    {
        self::assertSame($name, $alg->name());
        self::assertSame(AlgorithmFamily::EcdhEs, $alg->family());
        self::assertSame($mode, $alg->mode());
    }

    /** @return iterable<string, array{string, ContentEncryptionAlgorithm}> */
    public static function directProvider(): iterable
    {
        yield 'P-256 + A128GCM' => ['prime256v1', new A128Gcm()];
        yield 'P-384 + A256GCM' => ['secp384r1', new A256Gcm()];
        // A256CBC-HS512 needs a 64-byte CEK → two Concat KDF rounds.
        yield 'P-521 + A256CBC-HS512' => ['secp521r1', new A256CbcHs512()];
    }

    #[DataProvider('directProvider')]
    public function testDirectRoundTrip(string $opensslCurve, ContentEncryptionAlgorithm $enc): void
    {
        $recipient = self::ecKey($opensslCurve, 'ECDH-ES');

        $result = (new EcdhEs())->encryptKey($recipient->toPublicKey(), $enc);

        // Direct agreement: the derived key IS the CEK; no Encrypted Key.
        self::assertSame($enc->cekByteLength(), strlen($result->cek));
        self::assertSame('', $result->encryptedKey);
        $epk = $result->headerParameters['epk'];
        self::assertIsArray($epk);
        self::assertSame(['kty', 'crv', 'x', 'y'], array_keys($epk));

        $cek = (new EcdhEs())->decryptKey($recipient, $enc, '', $result->headerParameters);
        self::assertSame($result->cek, $cek);
    }

    #[DataProvider('kwProvider')]
    public function testKeyWrappingRoundTrip(EcdhEsAesKw $alg, string $name, KeyManagementMode $mode): void
    {
        self::assertSame(KeyManagementMode::KeyAgreementWithKeyWrapping, $mode);
        $recipient = self::ecKey('prime256v1', $name);
        $enc = new A256Gcm();

        $result = $alg->encryptKey($recipient->toPublicKey(), $enc);

        self::assertSame($enc->cekByteLength(), strlen($result->cek));
        self::assertNotSame('', $result->encryptedKey); // wrapped CEK travels in the Encrypted Key
        self::assertArrayHasKey('epk', $result->headerParameters);

        $cek = $alg->decryptKey($recipient, $enc, $result->encryptedKey, $result->headerParameters);
        self::assertSame($result->cek, $cek);
    }

    public function testDirectRejectsNonEmptyEncryptedKey(): void
    {
        $recipient = self::ecKey('prime256v1', 'ECDH-ES');
        $epk = (new EcdhEs())->encryptKey($recipient->toPublicKey(), new A128Gcm())->headerParameters;

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/must not carry a JWE Encrypted Key/');

        (new EcdhEs())->decryptKey($recipient, new A128Gcm(), 'unexpected', $epk);
    }

    public function testDecryptStripsNonSpecEpkFields(): void
    {
        $recipient = self::ecKey('prime256v1', 'ECDH-ES');
        $result = (new EcdhEs())->encryptKey($recipient->toPublicKey(), new A128Gcm());

        $epk = $result->headerParameters['epk'];
        self::assertIsArray($epk);
        // `use` + `key_ops` together violate RFC 7517 §4.3 and would make
        // EcPublicKey reject the JWK — unless parseEpk strips them first.
        $epk['use'] = 'enc';
        $epk['key_ops'] = ['deriveKey'];

        $cek = (new EcdhEs())->decryptKey($recipient, new A128Gcm(), '', ['epk' => $epk]);

        self::assertSame($result->cek, $cek);
    }

    public function testDecryptRejectsMissingEpk(): void
    {
        $recipient = self::ecKey('prime256v1', 'ECDH-ES');

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/missing the "epk"/');

        (new EcdhEs())->decryptKey($recipient, new A128Gcm(), '', ['alg' => 'ECDH-ES', 'enc' => 'A128GCM']);
    }

    /**
     * Invalid-curve attack (Sanso): an `epk` whose point is not on the curve
     * must be refused before it ever touches the static private key.
     */
    public function testDecryptRejectsOffCurveEpk(): void
    {
        $recipient = self::ecKey('prime256v1', 'ECDH-ES');
        // (0, 0) is a valid-length P-256 coordinate pair but not on the curve.
        $zero = Base64Url::encode(str_repeat("\x00", 32));

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/not a valid public key on a supported curve/');

        (new EcdhEs())->decryptKey($recipient, new A128Gcm(), '', [
            'epk' => ['kty' => 'EC', 'crv' => 'P-256', 'x' => $zero, 'y' => $zero],
        ]);
    }

    public function testDecryptRejectsEpkOnWrongCurve(): void
    {
        $recipient = self::ecKey('prime256v1', 'ECDH-ES');
        // A well-formed P-384 epk offered to a P-256 recipient.
        $foreign = self::ecKey('secp384r1', 'ECDH-ES')->toPublicKey()->toJwk();
        $epk = ['kty' => 'EC', 'crv' => 'P-384', 'x' => $foreign['x'], 'y' => $foreign['y']];

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/"epk" curve "P-384" does not match.*"P-256"/');

        (new EcdhEs())->decryptKey($recipient, new A128Gcm(), '', ['epk' => $epk]);
    }

    public function testEncryptRejectsNonEcKey(): void
    {
        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/ECDH-ES requires an EC key/');

        (new EcdhEs())->encryptKey(HmacKey::fromBinary(random_bytes(32), 'HS256'), new A128Gcm());
    }

    public function testDecryptRejectsPublicKey(): void
    {
        $public = self::ecKey('prime256v1', 'ECDH-ES')->toPublicKey();

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/decryption requires an EC private key/');

        (new EcdhEs())->decryptKey($public, new A128Gcm(), '', ['epk' => []]);
    }

    public function testRejectsKeyBoundToDifferentAlgorithm(): void
    {
        // A key bound to ECDH-ES+A128KW cannot be used for direct ECDH-ES.
        $recipient = self::ecKey('prime256v1', 'ECDH-ES+A128KW');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/ECDH-ES\+A128KW.*ECDH-ES|cannot be used/');

        (new EcdhEs())->encryptKey($recipient->toPublicKey(), new A128Gcm());
    }

    public function testEncryptAcceptsAnEcPrivateKey(): void
    {
        // The sender needs only the recipient's public point, but passing the
        // private key works too (its public part is taken).
        $recipient = self::ecKey('prime256v1', 'ECDH-ES');

        $result = (new EcdhEs())->encryptKey($recipient, new A128Gcm());

        self::assertSame($result->cek, (new EcdhEs())->decryptKey($recipient, new A128Gcm(), '', $result->headerParameters));
    }

    public function testEnforcesKeyOpsOnDerive(): void
    {
        $recipient = self::ecKey('prime256v1', 'ECDH-ES', ['wrapKey']);

        $this->expectException(KeyMismatchException::class);
        // The message names the offending key by its kid, not the "(no kid)" fallback.
        $this->expectExceptionMessageMatches('/Key ec-1 does not permit operation "deriveKey"/');

        (new EcdhEs())->encryptKey($recipient->toPublicKey(), new A128Gcm());
    }

    public function testDecryptRejectsKeyBoundToDifferentAlgorithm(): void
    {
        // The alg binding is checked before the epk is even parsed.
        $recipient = self::ecKey('prime256v1', 'ECDH-ES+A128KW');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/ECDH-ES\+A128KW.*ECDH-ES|cannot be used/');

        (new EcdhEs())->decryptKey($recipient, new A128Gcm(), '', ['epk' => []]);
    }

    public function testDecryptEnforcesKeyOps(): void
    {
        $recipient = self::ecKey('prime256v1', 'ECDH-ES', ['wrapKey']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/Key ec-1 does not permit operation "deriveKey"/');

        (new EcdhEs())->decryptKey($recipient, new A128Gcm(), '', ['epk' => []]);
    }

    /**
     * @param list<string>|null $keyOps
     */
    private static function ecKey(string $opensslCurve, string $alg, ?array $keyOps = null): EcPrivateKey
    {
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $opensslCurve,
        ]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $resource);
        openssl_pkey_export($resource, $pem);

        return EcPrivateKey::fromPem($pem, $alg, kid: 'ec-1', keyOps: $keyOps);
    }
}
