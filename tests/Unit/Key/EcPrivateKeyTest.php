<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\EcKey;
use Medzuch\Jwt\Key\EcPrivateKey;
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

#[CoversClass(EcPrivateKey::class)]
#[CoversClass(EcKey::class)]
#[UsesClass(EcPublicKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(EcCurve::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class EcPrivateKeyTest extends TestCase
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
            self::assertIsString($details['ec']['d']);

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
                    'd' => Base64Url::encode($pad($details['ec']['d'])),
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
    public function testFromPemLoadsPrivateKey(string $curve, string $alg): void
    {
        $key = EcPrivateKey::fromPem(self::$material[$curve]['privatePem'], $alg, kid: 'kp');

        self::assertSame($alg, $key->alg());
        self::assertSame('kp', $key->kid());
        self::assertSame($curve, $key->curve()->jwkName);
    }

    public function testFromPemRejectsPublicPem(): void
    {
        $this->expectException(InvalidKeyException::class);

        EcPrivateKey::fromPem(self::$material['P-256']['publicPem'], 'ES256');
    }

    public function testFromPemRejectsGarbage(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/Failed to load/');

        EcPrivateKey::fromPem("-----BEGIN EC PRIVATE KEY-----\nnot-a-key\n-----END EC PRIVATE KEY-----", 'ES256');
    }

    public function testFromPemRejectsNonEcKey(): void
    {
        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertNotFalse($rsa);
        $rsaPem = '';
        self::assertTrue(openssl_pkey_export($rsa, $rsaPem));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not an EC key/');

        EcPrivateKey::fromPem($rsaPem, 'ES256');
    }

    public function testFromPemRejectsCurveMismatchedToAlg(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/curve "P-256".*algorithm "ES384"/');

        EcPrivateKey::fromPem(self::$material['P-256']['privatePem'], 'ES384');
    }

    #[DataProvider('curveAndAlg')]
    public function testFromJwkLoadsPrivateKey(string $curve, string $alg): void
    {
        $key = EcPrivateKey::fromJwk(self::$material[$curve]['jwk']);

        self::assertSame($alg, $key->alg());
        self::assertSame($curve, $key->curve()->jwkName);
    }

    public function testFromJwkRejectsWrongKty(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        $jwk['kty'] = 'oct';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/requires kty "EC".*"oct"/');

        EcPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsCurveAlgMismatch(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        $jwk['alg'] = 'ES512';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/crv "P-256" pairs with alg "ES256", got "ES512"/');

        EcPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRequiresDAndPointsCallerAtEcPublicKey(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        unset($jwk['d']);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/does not contain "d".*EcPublicKey::fromJwk/');

        EcPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsWrongCoordinateLength(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        $jwk['d'] = Base64Url::encode(str_repeat("\x01", 33));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"d" must be 32 bytes for P-256, got 33/');

        EcPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsInvalidBase64InD(): void
    {
        $jwk = self::$material['P-256']['jwk'];
        $jwk['d'] = 'has spaces';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        EcPrivateKey::fromJwk($jwk);
    }

    #[DataProvider('curveAndAlg')]
    public function testToJwkRoundTrip(string $curve, string $alg): void
    {
        $loaded = EcPrivateKey::fromJwk(self::$material[$curve]['jwk']);
        $jwk = $loaded->toJwk();

        self::assertSame('EC', $jwk['kty']);
        self::assertSame($alg, $jwk['alg']);
        self::assertSame($curve, $jwk['crv']);
        self::assertArrayHasKey('x', $jwk);
        self::assertArrayHasKey('y', $jwk);
        self::assertArrayHasKey('d', $jwk);

        // Components must match the input JWK exactly — no precision loss
        // through the PEM round-trip.
        self::assertSame(self::$material[$curve]['jwk']['x'], $jwk['x']);
        self::assertSame(self::$material[$curve]['jwk']['y'], $jwk['y']);
        self::assertSame(self::$material[$curve]['jwk']['d'], $jwk['d']);

        $reloaded = EcPrivateKey::fromJwk($jwk);
        self::assertSame($loaded->toJwk(), $reloaded->toJwk());
    }

    public function testToJwkOmitsOptionalAttributesWhenAbsent(): void
    {
        $jwk = EcPrivateKey::fromPem(self::$material['P-256']['privatePem'], 'ES256')->toJwk();

        self::assertSame(['kty', 'alg', 'crv', 'x', 'y', 'd'], array_keys($jwk));
    }

    public function testToJwkIncludesKeyOps(): void
    {
        $key = EcPrivateKey::fromPem(self::$material['P-256']['privatePem'], 'ES256', keyOps: ['sign']);
        self::assertSame(['sign'], $key->toJwk()['key_ops']);
    }

    public function testToPublicKeyDropsPrivateScalar(): void
    {
        $priv = EcPrivateKey::fromJwk(self::$material['P-256']['jwk']);
        $pub = $priv->toPublicKey();

        self::assertArrayNotHasKey('d', $pub->toJwk());
        // The public coordinates must match — the derived key is the
        // same point on the curve.
        self::assertSame($priv->toJwk()['x'], $pub->toJwk()['x']);
        self::assertSame($priv->toJwk()['y'], $pub->toJwk()['y']);
    }
}
