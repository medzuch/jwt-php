<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use LogicException;
use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\AsymmetricKey;
use Medzuch\Jwt\Key\EcKey;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\EcCurve;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Key\RsaKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Key\SymmetricKey;
use Medzuch\Jwt\Key\Thumbprint;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\ConstantTime;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Tests\Support\ForeignJwkKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Thumbprint::class)]
#[UsesClass(AsymmetricKey::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(ConstantTime::class)]
#[UsesClass(EcCurve::class)]
#[UsesClass(EcKey::class)]
#[UsesClass(EcPrivateKey::class)]
#[UsesClass(EcPublicKey::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(Json::class)]
#[UsesClass(Key::class)]
#[UsesClass(OctKey::class)]
#[UsesClass(RsaKey::class)]
#[UsesClass(RsaPrivateKey::class)]
#[UsesClass(RsaPublicKey::class)]
final class ThumbprintTest extends TestCase
{
    public function testRsaPrivateAndPublicHalvesShareOneThumbprint(): void
    {
        $private = RsaPrivateKey::fromPem(self::pem(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]), 'RS256');

        self::assertSame(Thumbprint::of($private->toPublicKey()), Thumbprint::of($private));
    }

    public function testEcPrivateAndPublicHalvesShareOneThumbprint(): void
    {
        $private = EcPrivateKey::fromPem(self::pem(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']), 'ES256');

        self::assertSame(Thumbprint::of($private->toPublicKey()), Thumbprint::of($private));
    }

    public function testEcThumbprintIsTakenOverCrvKtyXYInOrder(): void
    {
        $jwk = EcPrivateKey::fromPem(self::pem(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']), 'ES256')
            ->toPublicKey()
            ->toJwk();
        self::assertIsString($jwk['x']);
        self::assertIsString($jwk['y']);

        $expected = Base64Url::encode(hash(
            'sha256',
            sprintf('{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}', $jwk['x'], $jwk['y']),
            true,
        ));

        self::assertSame($expected, Thumbprint::of(EcPublicKey::fromJwk($jwk)));
    }

    public function testNonRequiredMembersDoNotReachTheDigest(): void
    {
        $jwk = RsaPrivateKey::fromPem(self::pem(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]), 'RS256')
            ->toPublicKey()
            ->toJwk();

        $bare = RsaPublicKey::fromJwk($jwk);
        $decorated = RsaPublicKey::fromJwk([...$jwk, 'kid' => 'k-2026', 'use' => KeyUse::Sig->value]);

        self::assertSame(Thumbprint::of($bare), Thumbprint::of($decorated));
    }

    public function testPemAndJwkConstructionsOfOneKeyAgree(): void
    {
        $private = EcPrivateKey::fromPem(self::pem(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']), 'ES384');
        $fromJwk = EcPublicKey::fromJwk($private->toPublicKey()->toJwk());

        self::assertSame(Thumbprint::of($private->toPublicKey()), Thumbprint::of($fromJwk));
    }

    /** @return iterable<string, array{Key}> */
    public static function symmetricKeyProvider(): iterable
    {
        yield 'HmacKey' => [HmacKey::fromBinary(str_repeat("\x01", 32), 'HS256')];
        yield 'OctKey' => [OctKey::fromBinary(str_repeat("\x01", 32), 'A256KW')];
        yield 'foreign key emitting oct' => [new ForeignJwkKey(['kty' => 'oct', 'k' => 'c2VjcmV0'])];
    }

    #[DataProvider('symmetricKeyProvider')]
    public function testSymmetricKeysAreRefused(Key $key): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('symmetric');

        Thumbprint::of($key);
    }

    public function testSymmetricKeyIsRefusedBeforeItsSecretIsEncoded(): void
    {
        $key = new class ('HS256') extends SymmetricKey {
            public function __construct(string $alg)
            {
                parent::__construct($alg);
            }

            public function toJwk(): array
            {
                throw new LogicException('toJwk() must not be called on a symmetric key being thumbprinted');
            }
        };

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('symmetric');

        Thumbprint::of($key);
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function malformedJwkProvider(): iterable
    {
        yield 'unknown kty' => [['kty' => 'XYZ', 'x' => 'AQAB'], 'unknown "kty"'];
        yield 'missing kty' => [['n' => 'AQAB', 'e' => 'AQAB'], 'unknown "kty"'];
        yield 'non-string kty' => [['kty' => ['RSA'], 'n' => 'AQAB', 'e' => 'AQAB'], 'unknown "kty"'];
        yield 'RSA without e' => [['kty' => 'RSA', 'n' => 'AQAB'], '"RSA" key without its "e" member'];
        yield 'EC without y' => [['kty' => 'EC', 'crv' => 'P-256', 'x' => 'AQAB'], '"EC" key without its "y" member'];
        yield 'OKP with empty x' => [['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => ''], '"OKP" key without its "x" member'];
        yield 'OKP with non-string crv' => [['kty' => 'OKP', 'crv' => 1, 'x' => 'AQAB'], '"OKP" key without its "crv" member'];
    }

    /** @param array<string, mixed> $jwk */
    #[DataProvider('malformedJwkProvider')]
    public function testForeignKeysWithUnusableJwkAreRefused(array $jwk, string $message): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage($message);

        Thumbprint::of(new ForeignJwkKey($jwk));
    }

    public function testForeignKeyWithCompleteJwkIsThumbprinted(): void
    {
        $key = new ForeignJwkKey(['x' => 'AQAB', 'kty' => 'OKP', 'crv' => 'Ed25519', 'alg' => 'EdDSA']);

        self::assertSame(
            Base64Url::encode(hash('sha256', '{"crv":"Ed25519","kty":"OKP","x":"AQAB"}', true)),
            Thumbprint::of($key),
        );
    }

    public function testMatches(): void
    {
        $key = EcPrivateKey::fromPem(self::pem(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']), 'ES256');
        $thumbprint = Thumbprint::of($key);

        self::assertTrue(Thumbprint::matches($key, $thumbprint));
        self::assertFalse(Thumbprint::matches($key, strrev($thumbprint)));
        self::assertFalse(Thumbprint::matches($key, $thumbprint . 'A'));
        self::assertFalse(Thumbprint::matches($key, ''));
    }

    public function testMatchesRefusesSymmetricKeysRatherThanAnsweringFalse(): void
    {
        $this->expectException(InvalidKeyException::class);

        Thumbprint::matches(HmacKey::fromBinary(str_repeat("\x01", 32), 'HS256'), 'anything');
    }

    /** @param array<string, mixed> $options */
    private static function pem(array $options): string
    {
        $key = openssl_pkey_new($options);
        self::assertNotFalse($key);
        self::assertTrue(openssl_pkey_export($key, $pem));
        self::assertIsString($pem);

        return $pem;
    }
}
