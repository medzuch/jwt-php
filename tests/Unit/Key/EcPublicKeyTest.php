<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\EcKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\EcCurve;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(EcPublicKey::class)]
#[CoversClass(EcKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(EcCurve::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class EcPublicKeyTest extends TestCase
{
    /** @var array<string, array{publicPem: string, privatePem: string, jwk: array<string, mixed>}> */
    private static array $material;

    public static function setUpBeforeClass(): void
    {
        self::$material = [];
        foreach (
            [
                'P-256' => ['prime256v1', 'ES256', 32],
                'P-384' => ['secp384r1', 'ES384', 48],
                'P-521' => ['secp521r1', 'ES512', 66],
            ] as $jwkCurve => [$opensslCurve, $alg, $size]
        ) {
            $priv = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $opensslCurve]);
            self::assertNotFalse($priv);
            $privatePem = '';
            self::assertTrue(openssl_pkey_export($priv, $privatePem));

            $details = openssl_pkey_get_details($priv);
            self::assertIsArray($details);
            $publicPem = $details['key'];
            self::assertIsArray($details['ec']);
            self::assertIsString($details['ec']['x']);
            self::assertIsString($details['ec']['y']);

            $pad = static fn(string $b) => str_pad($b, $size, "\x00", STR_PAD_LEFT);

            self::$material[$jwkCurve] = [
                'publicPem' => $publicPem,
                'privatePem' => $privatePem,
                'jwk' => [
                    'kty' => 'EC',
                    'alg' => $alg,
                    'crv' => $jwkCurve,
                    'kid' => 'ec-' . strtolower($jwkCurve),
                    'x' => Base64Url::encode($pad($details['ec']['x'])),
                    'y' => Base64Url::encode($pad($details['ec']['y'])),
                ],
            ];
        }
    }

    /** @return iterable<string, array{string, string}> */
    public static function curveAndAlg(): iterable
    {
        yield 'P-256' => ['P-256', 'ES256'];
        yield 'P-384' => ['P-384', 'ES384'];
        yield 'P-521' => ['P-521', 'ES512'];
    }

    #[DataProvider('curveAndAlg')]
    public function testFromPemLoadsPublicKey(string $curve, string $alg): void
    {
        $key = EcPublicKey::fromPem(self::$material[$curve]['publicPem'], $alg, kid: 'k');

        self::assertSame($alg, $key->alg());
        self::assertSame('k', $key->kid());
        self::assertSame($curve, $key->curve()->jwkName);
    }

    public function testFromPemRejectsPrivatePem(): void
    {
        $this->expectException(InvalidKeyException::class);

        EcPublicKey::fromPem(self::$material['P-256']['privatePem'], 'ES256');
    }

    public function testFromPemRejectsGarbage(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/Failed to load/');

        EcPublicKey::fromPem("-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----", 'ES256');
    }

    public function testFromPemRejectsNonEcKey(): void
    {
        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertNotFalse($rsa);
        $details = openssl_pkey_get_details($rsa);
        self::assertIsArray($details);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not an EC key/');

        EcPublicKey::fromPem($details['key'], 'ES256');
    }

    public function testFromPemRejectsCurveMismatchedToAlg(): void
    {
        // Real P-256 PEM, but caller declares alg=ES384.
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/curve "P-256".*algorithm "ES384"/');

        EcPublicKey::fromPem(self::$material['P-256']['publicPem'], 'ES384');
    }

    #[DataProvider('curveAndAlg')]
    public function testFromJwkLoadsPublicKey(string $curve, string $alg): void
    {
        $key = EcPublicKey::fromJwk(self::$material[$curve]['jwk']);

        self::assertSame($alg, $key->alg());
        self::assertSame('ec-' . strtolower($curve), $key->kid());
        self::assertSame($curve, $key->curve()->jwkName);
    }

    public function testFromJwkRejectsPrivateJwk(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        $jwk['d'] = Base64Url::encode(str_repeat("\x01", 32));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/EcPrivateKey/');

        EcPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsWrongKty(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        $jwk['kty'] = 'RSA';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/requires kty "EC".*"RSA"/');

        EcPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsCurveAlgMismatch(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        $jwk['alg'] = 'ES384';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/crv "P-256" pairs with alg "ES256", got "ES384"/');

        EcPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsWrongCoordinateLength(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        $jwk['x'] = Base64Url::encode(str_repeat("\x01", 31));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"x" must be 32 bytes for P-256, got 31/');

        EcPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsInvalidBase64InCoordinate(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        $jwk['x'] = 'has spaces';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        EcPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsOffCurvePoint(): void
    {
        // x and y that satisfy length but don't lie on P-256: OpenSSL
        // rejects this at PEM load.
        $jwk = self::$material['P-256']['jwk'];
        $jwk['x'] = Base64Url::encode(str_repeat("\x01", 32));
        $jwk['y'] = Base64Url::encode(str_repeat("\x02", 32));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/Failed to load/');

        EcPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRequiresCrv(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        unset($jwk['crv']);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"crv"/');

        EcPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRequiresAlg(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        unset($jwk['alg']);

        $this->expectException(InvalidKeyException::class);

        EcPublicKey::fromJwk($jwk);
    }

    #[DataProvider('curveAndAlg')]
    public function testToJwkRoundTrip(string $curve, string $alg): void
    {
        $loaded = EcPublicKey::fromJwk(self::$material[$curve]['jwk']);

        $jwk = $loaded->toJwk();

        self::assertSame('EC', $jwk['kty']);
        self::assertSame($alg, $jwk['alg']);
        self::assertSame($curve, $jwk['crv']);
        self::assertArrayHasKey('x', $jwk);
        self::assertArrayHasKey('y', $jwk);
        self::assertArrayNotHasKey('d', $jwk);

        $reloaded = EcPublicKey::fromJwk($jwk);
        self::assertSame($loaded->toJwk(), $reloaded->toJwk());
    }

    public function testToJwkOmitsOptionalAttributesWhenAbsent(): void
    {
        $jwk = EcPublicKey::fromPem(self::$material['P-256']['publicPem'], 'ES256')->toJwk();

        self::assertSame(['kty', 'alg', 'crv', 'x', 'y'], array_keys($jwk));
    }

    public function testToJwkIncludesUseAndKeyOps(): void
    {
        $sig = EcPublicKey::fromPem(self::$material['P-256']['publicPem'], 'ES256', use: KeyUse::Sig);
        self::assertSame('sig', $sig->toJwk()['use']);

        $ops = EcPublicKey::fromPem(self::$material['P-256']['publicPem'], 'ES256', keyOps: ['verify']);
        self::assertSame(['verify'], $ops->toJwk()['key_ops']);
    }
}
