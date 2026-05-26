<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwe;

use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\Encryption\A128CbcHs256;
use Medzuch\Jwt\Algorithm\Encryption\A128Gcm;
use Medzuch\Jwt\Algorithm\Encryption\A192CbcHs384;
use Medzuch\Jwt\Algorithm\Encryption\A192Gcm;
use Medzuch\Jwt\Algorithm\Encryption\A256CbcHs512;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A128GcmKw;
use Medzuch\Jwt\Algorithm\KeyManagement\A128Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\A192GcmKw;
use Medzuch\Jwt\Algorithm\KeyManagement\A192Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\A256GcmKw;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\Dir;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEs;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEsA128Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEsA256Kw;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Exception\AlgorithmNotAllowedException;
use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jwe\CompactSerializer;
use Medzuch\Jwt\Jwe\Decrypter;
use Medzuch\Jwt\Jwe\Encrypter;
use Medzuch\Jwt\Jwe\ParsedJwe;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Encrypter::class)]
#[CoversClass(Decrypter::class)]
#[UsesClass(CompactSerializer::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\CompactJwe::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\ParsedJwe::class)]
#[UsesClass(Dir::class)]
#[UsesClass(A128Kw::class)]
#[UsesClass(A192Kw::class)]
#[UsesClass(A256Kw::class)]
#[UsesClass(A128GcmKw::class)]
#[UsesClass(A192GcmKw::class)]
#[UsesClass(A256GcmKw::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\AesKw::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\AesGcmKw::class)]
#[UsesClass(EcdhEs::class)]
#[UsesClass(EcdhEsA128Kw::class)]
#[UsesClass(EcdhEsA256Kw::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\EcdhEsAesKw::class)]
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
#[UsesClass(A192Gcm::class)]
#[UsesClass(A256Gcm::class)]
#[UsesClass(A128CbcHs256::class)]
#[UsesClass(A192CbcHs384::class)]
#[UsesClass(A256CbcHs512::class)]
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
#[UsesClass(\Medzuch\Jwt\Primitives\Base64Url::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Json::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Random::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Utf8::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\ConstantTime::class)]
final class EncrypterDecrypterTest extends TestCase
{
    private const PLAINTEXT = '{"sub":"user-1","scope":"read write"}';

    /** @return iterable<string, array{ContentEncryptionAlgorithm, positive-int}> */
    public static function encProvider(): iterable
    {
        yield 'A128GCM' => [new A128Gcm(), 16];
        yield 'A192GCM' => [new A192Gcm(), 24];
        yield 'A256GCM' => [new A256Gcm(), 32];
        yield 'A128CBC-HS256' => [new A128CbcHs256(), 32];
        yield 'A192CBC-HS384' => [new A192CbcHs384(), 48];
        yield 'A256CBC-HS512' => [new A256CbcHs512(), 64];
    }

    #[DataProvider('encProvider')]
    public function testDirRoundTrip(ContentEncryptionAlgorithm $enc, int $cekBytes): void
    {
        $key = OctKey::fromBinary(random_bytes($enc->cekByteLength()), $enc->name(), kid: 'k1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($key));

        $jwe = (new Encrypter())->encrypt(new Dir(), $enc, ['typ' => 'JWT', 'kid' => 'k1'], self::PLAINTEXT, $key);

        $parsed = CompactSerializer::deserialize($jwe->value);
        self::assertSame('dir', $parsed->header['alg']);
        self::assertSame($enc->name(), $parsed->header['enc']);
        self::assertSame('', $parsed->encryptedKey); // dir carries no Encrypted Key

        $plaintext = (new Decrypter())->decrypt($parsed, [new Dir()], self::allEnc(), $resolver);

        self::assertSame(self::PLAINTEXT, $plaintext);
    }

    /** @return iterable<string, array{KeyManagementAlgorithm, string, int, ContentEncryptionAlgorithm}> */
    public static function wrappingProvider(): iterable
    {
        $enc = new A128CbcHs256();
        yield 'A128KW + A128CBC-HS256' => [new A128Kw(), 'A128KW', 16, $enc];
        yield 'A192KW + A128CBC-HS256' => [new A192Kw(), 'A192KW', 24, $enc];
        yield 'A256KW + A256GCM' => [new A256Kw(), 'A256KW', 32, new A256Gcm()];
        yield 'A128GCMKW + A256GCM' => [new A128GcmKw(), 'A128GCMKW', 16, new A256Gcm()];
        yield 'A192GCMKW + A192CBC-HS384' => [new A192GcmKw(), 'A192GCMKW', 24, new A192CbcHs384()];
        yield 'A256GCMKW + A256CBC-HS512' => [new A256GcmKw(), 'A256GCMKW', 32, new A256CbcHs512()];
    }

    #[DataProvider('wrappingProvider')]
    public function testKeyWrappingRoundTrip(KeyManagementAlgorithm $alg, string $algName, int $kekBytes, ContentEncryptionAlgorithm $enc): void
    {
        // The KEK is bound to the key-management algorithm (not the `enc`).
        $kek = OctKey::fromBinary(random_bytes(max(1, $kekBytes)), $algName, kid: 'k1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($kek));

        $jwe = (new Encrypter())->encrypt($alg, $enc, ['typ' => 'JWT', 'kid' => 'k1'], self::PLAINTEXT, $kek);

        $parsed = CompactSerializer::deserialize($jwe->value);
        self::assertSame($algName, $parsed->header['alg']);
        self::assertSame($enc->name(), $parsed->header['enc']);
        self::assertNotSame('', $parsed->encryptedKey); // wrapping ships a JWE Encrypted Key

        $plaintext = (new Decrypter())->decrypt($parsed, [$alg], self::allEnc(), $resolver);

        self::assertSame(self::PLAINTEXT, $plaintext);
    }

    /** @return iterable<string, array{KeyManagementAlgorithm, string, string, ContentEncryptionAlgorithm}> */
    public static function ecdhProvider(): iterable
    {
        yield 'ECDH-ES (P-256) + A128GCM' => [new EcdhEs(), 'ECDH-ES', 'prime256v1', new A128Gcm()];
        yield 'ECDH-ES (P-521) + A256CBC-HS512' => [new EcdhEs(), 'ECDH-ES', 'secp521r1', new A256CbcHs512()];
        yield 'ECDH-ES+A128KW (P-256) + A128GCM' => [new EcdhEsA128Kw(), 'ECDH-ES+A128KW', 'prime256v1', new A128Gcm()];
        yield 'ECDH-ES+A256KW (P-384) + A256GCM' => [new EcdhEsA256Kw(), 'ECDH-ES+A256KW', 'secp384r1', new A256Gcm()];
    }

    #[DataProvider('ecdhProvider')]
    public function testEcdhEsRoundTrip(KeyManagementAlgorithm $alg, string $algName, string $opensslCurve, ContentEncryptionAlgorithm $enc): void
    {
        $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $opensslCurve]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $resource);
        openssl_pkey_export($resource, $pem);
        $recipient = EcPrivateKey::fromPem((string) $pem, $algName, kid: 'ec-1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($recipient));

        // Encrypt to the recipient's public key; the ephemeral `epk` is emitted
        // into the protected header by the Encrypter.
        $jwe = (new Encrypter())->encrypt($alg, $enc, ['typ' => 'JWT', 'kid' => 'ec-1'], self::PLAINTEXT, $recipient->toPublicKey());

        $parsed = CompactSerializer::deserialize($jwe->value);
        self::assertSame($algName, $parsed->header['alg']);
        self::assertArrayHasKey('epk', $parsed->header);

        $plaintext = (new Decrypter())->decrypt($parsed, [$alg], self::allEnc(), $resolver);

        self::assertSame(self::PLAINTEXT, $plaintext);
    }

    public function testCallerSuppliedAlgConflictIsRejected(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1');

        $this->expectException(InvalidHeaderException::class);
        // The message quotes the offending string value and names the chosen alg.
        $this->expectExceptionMessageMatches('/"alg" "A128KW" does not match the chosen algorithm "dir"/');

        (new Encrypter())->encrypt(new Dir(), new A256Gcm(), ['alg' => 'A128KW'], self::PLAINTEXT, $key);
    }

    public function testCallerSuppliedEncConflictIsRejected(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"enc" "A128GCM" does not match the chosen algorithm "A256GCM"/');

        (new Encrypter())->encrypt(new Dir(), new A256Gcm(), ['enc' => 'A128GCM'], self::PLAINTEXT, $key);
    }

    public function testConflictMessageDescribesAnExplicitNullValue(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1');

        $this->expectException(InvalidHeaderException::class);
        // A JSON null offending value is rendered as the word `null`.
        $this->expectExceptionMessageMatches('/"alg" null does not match/');

        (new Encrypter())->encrypt(new Dir(), new A256Gcm(), ['alg' => null], self::PLAINTEXT, $key);
    }

    public function testConflictMessageDescribesANonStringValue(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1');

        $this->expectException(InvalidHeaderException::class);
        // A non-string offending value is rendered by its debug type.
        $this->expectExceptionMessageMatches('/"enc" \(int\) does not match/');

        (new Encrypter())->encrypt(new Dir(), new A256Gcm(), ['enc' => 42], self::PLAINTEXT, $key);
    }

    /** @return iterable<string, array{string}> */
    public static function reservedHeaderParamProvider(): iterable
    {
        yield 'alg' => ['alg'];
        yield 'enc' => ['enc'];
    }

    /**
     * A misbehaving scheme that tries to slip an `alg`/`enc` override through
     * its contributed header parameters must be rejected, not let it clobber
     * the value withAlgEnc already pinned.
     */
    #[DataProvider('reservedHeaderParamProvider')]
    public function testKeyManagementCannotSmuggleReservedHeaderParameters(string $reserved): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1');

        $rogue = new class ($reserved) implements \Medzuch\Jwt\Algorithm\KeyManagementAlgorithm {
            public function __construct(private readonly string $reserved) {}

            public function name(): string
            {
                return 'dir';
            }

            public function family(): \Medzuch\Jwt\Algorithm\AlgorithmFamily
            {
                return \Medzuch\Jwt\Algorithm\AlgorithmFamily::Direct;
            }

            public function mode(): \Medzuch\Jwt\Algorithm\KeyManagementMode
            {
                return \Medzuch\Jwt\Algorithm\KeyManagementMode::DirectEncryption;
            }

            public function encryptKey(\Medzuch\Jwt\Key\Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption): \Medzuch\Jwt\Algorithm\CekEncryptionResult
            {
                return new \Medzuch\Jwt\Algorithm\CekEncryptionResult(random_bytes($contentEncryption->cekByteLength()), '', [$this->reserved => 'smuggled']);
            }

            public function decryptKey(\Medzuch\Jwt\Key\Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption, string $encryptedKey, array $header): string
            {
                return random_bytes($contentEncryption->cekByteLength());
            }
        };

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches(sprintf('/must not contribute the reserved header parameter "%s"/', $reserved));

        (new Encrypter())->encrypt($rogue, new A256Gcm(), ['kid' => 'k1'], self::PLAINTEXT, $key);
    }

    public function testDecryptRefusesEncOutsideAllowlist(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($key));
        $jwe = (new Encrypter())->encrypt(new Dir(), new A256Gcm(), ['kid' => 'k1'], self::PLAINTEXT, $key);
        $parsed = CompactSerializer::deserialize($jwe->value);

        $this->expectException(AlgorithmNotAllowedException::class);
        $this->expectExceptionMessageMatches('/enc "A256GCM".*allowlist/');

        // Only A128GCM is accepted; the token's A256GCM must be refused.
        (new Decrypter())->decrypt($parsed, [new Dir()], [new A128Gcm()], $resolver);
    }

    public function testDecryptRefusesAlgOutsideAllowlist(): void
    {
        // Hand-assemble a structurally valid token whose alg is not "dir".
        $compact = CompactSerializer::serialize(
            ['alg' => 'A128KW', 'enc' => 'A256GCM'],
            'wrapped-key',
            random_bytes(12),
            'ciphertext',
            random_bytes(16),
        );
        $parsed = CompactSerializer::deserialize($compact->value);
        $resolver = new StaticJwkSetResolver(JwkSet::of(OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1')));

        $this->expectException(AlgorithmNotAllowedException::class);
        $this->expectExceptionMessageMatches('/alg "A128KW".*allowlist/');

        (new Decrypter())->decrypt($parsed, [new Dir()], self::allEnc(), $resolver);
    }

    public function testTamperedCiphertextIsRejected(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1');
        $resolver = new StaticJwkSetResolver(JwkSet::of($key));
        $jwe = (new Encrypter())->encrypt(new Dir(), new A256Gcm(), ['kid' => 'k1'], self::PLAINTEXT, $key);
        $parsed = CompactSerializer::deserialize($jwe->value);

        // Re-serialize with one ciphertext byte flipped.
        $ciphertext = $parsed->ciphertext;
        $ciphertext[0] = chr(ord($ciphertext[0]) ^ 0x01);
        $tampered = CompactSerializer::serialize($parsed->header, $parsed->encryptedKey, $parsed->iv, $ciphertext, $parsed->tag);

        $this->expectException(DecryptionException::class);

        (new Decrypter())->decrypt(CompactSerializer::deserialize($tampered->value), [new Dir()], self::allEnc(), $resolver);
    }

    public function testDecryptRejectsHeaderMissingAlg(): void
    {
        // A ParsedJwe built directly (bypassing the serializer) with no "alg".
        $parsed = new ParsedJwe('h', '', 'aXY', 'Y3Q', 'dGFn', ['enc' => 'A256GCM'], '', 'iv', 'ct', 'tag');
        $resolver = new StaticJwkSetResolver(JwkSet::of(OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1')));

        $this->expectException(InvalidHeaderException::class);

        (new Decrypter())->decrypt($parsed, [new Dir()], self::allEnc(), $resolver);
    }

    public function testDecryptRejectsHeaderWithEmptyEnc(): void
    {
        $parsed = new ParsedJwe('h', '', 'aXY', 'Y3Q', 'dGFn', ['alg' => 'dir', 'enc' => ''], '', 'iv', 'ct', 'tag');
        $resolver = new StaticJwkSetResolver(JwkSet::of(OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'k1')));

        $this->expectException(InvalidHeaderException::class);

        (new Decrypter())->decrypt($parsed, [new Dir()], self::allEnc(), $resolver);
    }

    /** @return non-empty-list<ContentEncryptionAlgorithm> */
    private static function allEnc(): array
    {
        return [new A128Gcm(), new A192Gcm(), new A256Gcm(), new A128CbcHs256(), new A192CbcHs384(), new A256CbcHs512()];
    }
}
