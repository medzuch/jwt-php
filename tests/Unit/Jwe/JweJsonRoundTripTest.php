<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwe;

use Medzuch\Jwt\Algorithm\Encryption\A128CbcHs256;
use Medzuch\Jwt\Algorithm\Encryption\A128Gcm;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A128Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\Dir;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEs;
use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Jwe\Decrypter;
use Medzuch\Jwt\Jwe\Encrypter;
use Medzuch\Jwt\Jwe\JsonSerializer;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end JSON-serialization round-trips: {@see Encrypter} JSON producers →
 * {@see JsonSerializer::deserialize()} → {@see Decrypter}. Proves the
 * JSON-specific machinery (the `aad` fold into the AAD, unprotected-header
 * resolution) interoperates with the real crypto path, complementing the
 * compact round-trips in {@see EncrypterDecrypterTest}.
 */
#[CoversClass(Encrypter::class)]
#[CoversClass(JsonSerializer::class)]
#[UsesClass(Decrypter::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\FlattenedJwe::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\GeneralJwe::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\ParsedJwe::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\Internal\JweHeader::class)]
#[UsesClass(Dir::class)]
#[UsesClass(A128Kw::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\AesKw::class)]
#[UsesClass(EcdhEs::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\Internal\EcdhKeyAgreement::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\Internal\ConcatKdf::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\Internal\AesKeyWrap::class)]
#[UsesClass(EcPrivateKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\EcPublicKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\EcKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\AsymmetricKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\Internal\EcCurve::class)]
#[UsesClass(\Medzuch\Jwt\Key\Internal\Asn1::class)]
#[UsesClass(\Medzuch\Jwt\Key\Internal\JwkAttributes::class)]
#[UsesClass(A128Gcm::class)]
#[UsesClass(A256Gcm::class)]
#[UsesClass(A128CbcHs256::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Encryption\AesGcm::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Encryption\AesCbcHmac::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\CekEncryptionResult::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\AlgorithmFamily::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagementMode::class)]
#[UsesClass(OctKey::class)]
#[UsesClass(JwkSet::class)]
#[UsesClass(StaticJwkSetResolver::class)]
#[UsesClass(\Medzuch\Jwt\Key\Key::class)]
#[UsesClass(\Medzuch\Jwt\Key\SymmetricKey::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(Json::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Random::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Utf8::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\ConstantTime::class)]
final class JweJsonRoundTripTest extends TestCase
{
    private const PLAINTEXT = '{"sub":"user-1","scope":"read write"}';

    public function testFlattenedDirRoundTrip(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($key));

        $jwe = (new Encrypter())->encryptFlattened(new Dir(), new A256Gcm(), ['typ' => 'JWT', 'kid' => 'k1'], self::PLAINTEXT, $key);

        $parsed = JsonSerializer::deserialize($jwe->value);
        $plaintext = (new Decrypter())->decrypt($parsed, [new Dir()], [new A256Gcm()], $resolver);

        self::assertSame(self::PLAINTEXT, $plaintext);
    }

    public function testGeneralKeyWrapRoundTrip(): void
    {
        $kek = OctKey::fromBinary(random_bytes(16), 'A128KW', kid: 'k1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($kek));

        $jwe = (new Encrypter())->encryptGeneral(new A128Kw(), new A128CbcHs256(), ['kid' => 'k1'], self::PLAINTEXT, $kek);

        // It really is the general shape (recipients array), not flattened.
        self::assertArrayHasKey('recipients', Json::decode($jwe->value));

        $parsed = JsonSerializer::deserialize($jwe->value);
        $plaintext = (new Decrypter())->decrypt($parsed, [new A128Kw()], [new A128CbcHs256()], $resolver);

        self::assertSame(self::PLAINTEXT, $plaintext);
    }

    public function testFlattenedWithAadRoundTrip(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($key));

        $jwe = (new Encrypter())->encryptFlattened(new Dir(), new A256Gcm(), ['kid' => 'k1'], self::PLAINTEXT, $key, aad: 'bound-context');

        $parsed = JsonSerializer::deserialize($jwe->value);
        self::assertSame(Base64Url::encode('bound-context'), $parsed->aad);

        $plaintext = (new Decrypter())->decrypt($parsed, [new Dir()], [new A256Gcm()], $resolver);
        self::assertSame(self::PLAINTEXT, $plaintext);
    }

    /**
     * The `aad` is authenticated: swapping it for a different value (re-encoded
     * into the JSON) must fail the content tag, not silently decrypt.
     */
    public function testTamperedAadIsRejected(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($key));

        $jwe = (new Encrypter())->encryptFlattened(new Dir(), new A256Gcm(), ['kid' => 'k1'], self::PLAINTEXT, $key, aad: 'bound-context');

        $object = Json::decode($jwe->value);
        $object['aad'] = Base64Url::encode('tampered-context');
        $tampered = Json::encode($object);

        $this->expectException(DecryptionException::class);

        (new Decrypter())->decrypt(JsonSerializer::deserialize($tampered), [new Dir()], [new A256Gcm()], $resolver);
    }

    /**
     * `kid` may travel in the (unauthenticated) shared unprotected header; the
     * recipient still resolves its key from the *effective* merged header.
     */
    public function testKidInUnprotectedHeaderResolvesTheKey(): void
    {
        $kek = OctKey::fromBinary(random_bytes(16), 'A128KW', kid: 'k1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($kek));

        $jwe = (new Encrypter())->encryptFlattened(
            new A128Kw(),
            new A128CbcHs256(),
            ['typ' => 'JWT'],
            self::PLAINTEXT,
            $kek,
            sharedUnprotected: ['kid' => 'k1'],
        );

        // kid is *not* in the protected header...
        $decoded = Json::decode($jwe->value);
        $protected = $decoded['protected'];
        self::assertIsString($protected);
        self::assertArrayNotHasKey('kid', Json::decode(Base64Url::decode($protected)));
        self::assertSame(['kid' => 'k1'], $decoded['unprotected']);

        // ...yet resolution and decryption still succeed.
        $plaintext = (new Decrypter())->decrypt(JsonSerializer::deserialize($jwe->value), [new A128Kw()], [new A128CbcHs256()], $resolver);
        self::assertSame(self::PLAINTEXT, $plaintext);
    }

    public function testEcdhEsFlattenedRoundTrip(): void
    {
        $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $resource);
        openssl_pkey_export($resource, $pem);
        $recipient = EcPrivateKey::fromPem((string) $pem, 'ECDH-ES', kid: 'ec-1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($recipient));

        $jwe = (new Encrypter())->encryptFlattened(new EcdhEs(), new A128Gcm(), ['kid' => 'ec-1'], self::PLAINTEXT, $recipient->toPublicKey());

        $parsed = JsonSerializer::deserialize($jwe->value);
        self::assertArrayHasKey('epk', $parsed->header); // epk is in the protected header

        $plaintext = (new Decrypter())->decrypt($parsed, [new EcdhEs()], [new A128Gcm()], $resolver);
        self::assertSame(self::PLAINTEXT, $plaintext);
    }
}
