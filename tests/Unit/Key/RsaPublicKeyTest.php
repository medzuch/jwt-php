<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\RsaKey;
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

#[CoversClass(RsaPublicKey::class)]
#[CoversClass(RsaKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class RsaPublicKeyTest extends TestCase
{
    /** @var array{public: string, private: string, jwk: array<string, mixed>} */
    private static array $material;

    public static function setUpBeforeClass(): void
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource, 'openssl_pkey_new failed');

        $privatePem = '';
        openssl_pkey_export($resource, $privatePem);

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        $publicPem = $details['key'];

        // Build the JWK for the public half from the OpenSSL params.
        $rsa = $details['rsa'];
        self::assertIsArray($rsa);
        self::assertIsString($rsa['n']);
        self::assertIsString($rsa['e']);
        $jwk = [
            'kty' => 'RSA',
            'alg' => 'RS256',
            'kid' => 'rsa-test',
            'n' => Base64Url::encode($rsa['n']),
            'e' => Base64Url::encode($rsa['e']),
        ];

        self::$material = [
            'public' => $publicPem,
            'private' => $privatePem,
            'jwk' => $jwk,
        ];
    }

    public function testFromPemLoadsPublicKey(): void
    {
        $key = RsaPublicKey::fromPem(self::$material['public'], 'RS256', kid: 'k');

        self::assertSame('RS256', $key->alg());
        self::assertSame('k', $key->kid());
    }

    public function testFromPemRejectsPrivatePem(): void
    {
        // openssl_pkey_get_public refuses a private PEM, so this surfaces
        // as a generic load failure — the message includes OpenSSL's
        // explanation.
        $this->expectException(InvalidKeyException::class);

        RsaPublicKey::fromPem(self::$material['private'], 'RS256');
    }

    public function testFromPemRejectsGarbage(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/Failed to load/');

        RsaPublicKey::fromPem("-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----", 'RS256');
    }

    public function testFromPemRejectsNonRsaKey(): void
    {
        // Generate a P-256 EC key and confirm RsaPublicKey refuses it.
        $ec = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        self::assertNotFalse($ec);
        $details = openssl_pkey_get_details($ec);
        self::assertIsArray($details);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not an RSA key/');

        RsaPublicKey::fromPem($details['key'], 'RS256');
    }

    public function testFromJwkLoadsPublicKey(): void
    {
        $key = RsaPublicKey::fromJwk(self::$material['jwk']);

        self::assertSame('RS256', $key->alg());
        self::assertSame('rsa-test', $key->kid());
    }

    public function testFromJwkRejectsPrivateJwk(): void
    {
        $jwk = self::$material['jwk'];
        $jwk['d'] = Base64Url::encode("\x01");

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/RsaPrivateKey/');

        RsaPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRequiresAlg(): void
    {
        $jwk = self::$material['jwk'];
        unset($jwk['alg']);

        $this->expectException(InvalidKeyException::class);

        RsaPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRequiresN(): void
    {
        $jwk = self::$material['jwk'];
        unset($jwk['n']);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"n"/');

        RsaPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRequiresE(): void
    {
        $jwk = self::$material['jwk'];
        unset($jwk['e']);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"e"/');

        RsaPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsInvalidBase64InN(): void
    {
        $jwk = self::$material['jwk'];
        $jwk['n'] = 'has spaces';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        RsaPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsEmptyN(): void
    {
        // Base64Url::decode('') returns ''; we should reject this rather
        // than passing empty bytes to OpenSSL.
        $jwk = self::$material['jwk'];
        $jwk['n'] = 'AA'; // base64url of "\x00" — non-empty input, but the
        // helper's "non-empty-string after decode" guard isn't tripped
        // here. The real "empty" path comes from a JWK with `n: ""`
        // which the JwkAttributes::requireString rejects first.
        // Verify the explicit empty-input path:
        $jwk['n'] = '';

        $this->expectException(InvalidKeyException::class);

        RsaPublicKey::fromJwk($jwk);
    }

    public function testToJwkRoundTrip(): void
    {
        $loaded = RsaPublicKey::fromPem(
            self::$material['public'],
            'RS256',
            kid: 'k1',
            use: KeyUse::Sig,
        );

        $jwk = $loaded->toJwk();

        self::assertSame('RSA', $jwk['kty']);
        self::assertSame('RS256', $jwk['alg']);
        self::assertSame('k1', $jwk['kid']);
        self::assertSame('sig', $jwk['use']);
        self::assertArrayHasKey('n', $jwk);
        self::assertArrayHasKey('e', $jwk);
        self::assertArrayNotHasKey('d', $jwk);

        $reloaded = RsaPublicKey::fromJwk($jwk);

        self::assertSame($loaded->toJwk(), $reloaded->toJwk());
    }

    public function testToJwkOmitsOptionalAttributesWhenAbsent(): void
    {
        $jwk = RsaPublicKey::fromPem(self::$material['public'], 'RS256')->toJwk();

        self::assertSame(['kty', 'alg', 'n', 'e'], array_keys($jwk));
    }

    public function testToJwkIncludesKeyOps(): void
    {
        $key = RsaPublicKey::fromPem(self::$material['public'], 'RS256', keyOps: ['verify']);

        self::assertSame(['verify'], $key->toJwk()['key_ops']);
    }

    public function testFromPemRejectsBelowMinimumKeySize(): void
    {
        // 1024-bit RSA has been factorable on commodity hardware for years.
        // The library refuses it per NIST SP 800-131A Rev. 2.
        $resource = openssl_pkey_new([
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource);
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/at least 2048 bits/');

        RsaPublicKey::fromPem($details['key'], 'RS256');
    }

    public function testFromJwkRejectsWrongKty(): void
    {
        $jwk = self::$material['jwk'];
        $jwk['kty'] = 'oct';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/requires kty "RSA".*"oct"/');

        RsaPublicKey::fromJwk($jwk);
    }
}
