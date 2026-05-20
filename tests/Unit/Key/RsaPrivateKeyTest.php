<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\RsaKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

use function array_keys;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;

#[CoversClass(RsaPrivateKey::class)]
#[CoversClass(RsaKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
#[UsesClass(RsaPublicKey::class)]
final class RsaPrivateKeyTest extends TestCase
{
    /** @var array{public: string, private: string} */
    private static array $material;

    public static function setUpBeforeClass(): void
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource);

        $privatePem = '';
        openssl_pkey_export($resource, $privatePem);
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        self::$material = [
            'public' => $details['key'],
            'private' => $privatePem,
        ];
    }

    public function testFromPemLoadsPrivateKey(): void
    {
        $key = RsaPrivateKey::fromPem(self::$material['private'], 'RS256');

        self::assertSame('RS256', $key->alg());
    }

    public function testFromPemRejectsPublicPem(): void
    {
        $this->expectException(InvalidKeyException::class);

        RsaPrivateKey::fromPem(self::$material['public'], 'RS256');
    }

    public function testFromPemRejectsGarbage(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/Failed to load/');

        RsaPrivateKey::fromPem(
            "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----",
            'RS256',
        );
    }

    public function testFromPemRejectsNonRsaKey(): void
    {
        $ec = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        self::assertNotFalse($ec);
        $ecPem = '';
        openssl_pkey_export($ec, $ecPem);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not an RSA key/');

        RsaPrivateKey::fromPem($ecPem, 'RS256');
    }

    public function testToJwkRoundTrip(): void
    {
        $original = RsaPrivateKey::fromPem(
            self::$material['private'],
            'RS256',
            kid: 'priv-1',
            use: KeyUse::Sig,
        );

        $jwk = $original->toJwk();

        self::assertSame('RSA', $jwk['kty']);
        self::assertSame('RS256', $jwk['alg']);
        self::assertSame('priv-1', $jwk['kid']);
        self::assertSame('sig', $jwk['use']);
        foreach (['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'] as $param) {
            self::assertArrayHasKey($param, $jwk, $param . ' missing from JWK');
        }

        $reloaded = RsaPrivateKey::fromJwk($jwk);

        // Re-export to confirm the round-trip preserves every component
        // bit-for-bit.
        self::assertSame($jwk, $reloaded->toJwk());
    }

    public function testToJwkOmitsOptionalsWhenAbsent(): void
    {
        $jwk = RsaPrivateKey::fromPem(self::$material['private'], 'RS256')->toJwk();

        self::assertSame(
            ['kty', 'alg', 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'],
            array_keys($jwk),
        );
    }

    public function testToJwkIncludesKeyOps(): void
    {
        $key = RsaPrivateKey::fromPem(self::$material['private'], 'RS256', keyOps: ['sign']);

        self::assertSame(['sign'], $key->toJwk()['key_ops']);
    }

    public function testFromJwkRequiresAllCrtParameters(): void
    {
        $full = RsaPrivateKey::fromPem(self::$material['private'], 'RS256')->toJwk();

        foreach (['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'] as $param) {
            $partial = $full;
            unset($partial[$param]);

            try {
                RsaPrivateKey::fromJwk($partial);
                self::fail("Expected exception when JWK is missing \"$param\"");
            } catch (InvalidKeyException $e) {
                self::assertStringContainsString("\"$param\"", $e->getMessage());
            }
        }
    }

    public function testFromJwkRejectsInvalidBase64InAnyComponent(): void
    {
        $full = RsaPrivateKey::fromPem(self::$material['private'], 'RS256')->toJwk();
        $full['p'] = 'has spaces';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        RsaPrivateKey::fromJwk($full);
    }

    public function testFromPemRejectsBelowMinimumKeySize(): void
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource);
        $pem = '';
        openssl_pkey_export($resource, $pem);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/at least 2048 bits/');

        RsaPrivateKey::fromPem($pem, 'RS256');
    }

    public function testFromJwkRejectsWrongKty(): void
    {
        $jwk = RsaPrivateKey::fromPem(self::$material['private'], 'RS256')->toJwk();
        $jwk['kty'] = 'oct';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/requires kty "RSA".*"oct"/');

        RsaPrivateKey::fromJwk($jwk);
    }

    public function testToPublicKeyDropsPrivateComponents(): void
    {
        $priv = RsaPrivateKey::fromPem(
            self::$material['private'],
            'RS256',
            kid: 'k1',
            use: KeyUse::Sig,
        );

        $pub = $priv->toPublicKey();
        $pubJwk = $pub->toJwk();

        self::assertSame('RSA', $pubJwk['kty']);
        self::assertSame('RS256', $pubJwk['alg']);
        self::assertSame('k1', $pubJwk['kid']);
        self::assertSame('sig', $pubJwk['use']);
        self::assertArrayHasKey('n', $pubJwk);
        self::assertArrayHasKey('e', $pubJwk);
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi'] as $secret) {
            self::assertArrayNotHasKey($secret, $pubJwk, $secret . ' must not appear in public JWK');
        }
    }
}
