<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\OkpKey;
use Medzuch\Jwt\Key\OkpPrivateKey;
use Medzuch\Jwt\Key\OkpPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OkpPrivateKey::class)]
#[CoversClass(OkpKey::class)]
#[UsesClass(OkpPublicKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class OkpPrivateKeyTest extends TestCase
{
    /**
     * RFC 8037 §A.1 — Ed25519 keypair.
     */
    private const X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';

    private const D = 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A';

    /** @return array<string, mixed> */
    private static function jwk(): array
    {
        return [
            'kty' => 'OKP',
            'alg' => 'EdDSA',
            'crv' => 'Ed25519',
            'kid' => 'kp-ed',
            'x' => self::X,
            'd' => self::D,
        ];
    }

    public function testFromJwkLoadsPrivateKey(): void
    {
        $key = OkpPrivateKey::fromJwk(self::jwk());

        self::assertSame('EdDSA', $key->alg());
        self::assertSame('Ed25519', $key->curve());
        self::assertSame('kp-ed', $key->kid());
        self::assertSame(64, strlen($key->secretKeyBytes()));
        self::assertSame(32, strlen($key->publicKeyBytes()));
    }

    public function testFromJwkRejectsWrongKty(): void
    {
        $jwk = self::jwk();
        $jwk['kty'] = 'RSA';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/requires kty "OKP".*"RSA"/');

        OkpPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRequiresDAndPointsCallerAtOkpPublicKey(): void
    {
        $jwk = self::jwk();
        unset($jwk['d']);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/does not contain "d".*OkpPublicKey::fromJwk/');

        OkpPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsWrongCurve(): void
    {
        $jwk = self::jwk();
        $jwk['crv'] = 'Ed448';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/supports crv "Ed25519".*"Ed448"/');

        OkpPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsWrongDLength(): void
    {
        $jwk = self::jwk();
        $jwk['d'] = Base64Url::encode(str_repeat("\x01", 33));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"d" must be 32 bytes for Ed25519, got 33/');

        OkpPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsWrongXLength(): void
    {
        $jwk = self::jwk();
        $jwk['x'] = Base64Url::encode(str_repeat("\x01", 31));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"x" must be 32 bytes for Ed25519, got 31/');

        OkpPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsInconsistentXAndD(): void
    {
        // Substitute a different x; the public derived from d will not match.
        $jwk = self::jwk();
        $jwk['x'] = Base64Url::encode(str_repeat("\x01", 32));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"x" does not match the public key derived from "d"/');

        OkpPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsInvalidBase64InD(): void
    {
        $jwk = self::jwk();
        $jwk['d'] = 'has spaces';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        OkpPrivateKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsInvalidBase64InX(): void
    {
        $jwk = self::jwk();
        $jwk['x'] = 'has spaces';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        OkpPrivateKey::fromJwk($jwk);
    }

    public function testToJwkRoundTrip(): void
    {
        $loaded = OkpPrivateKey::fromJwk(self::jwk());
        $jwk = $loaded->toJwk();

        self::assertSame('OKP', $jwk['kty']);
        self::assertSame('EdDSA', $jwk['alg']);
        self::assertSame('Ed25519', $jwk['crv']);
        self::assertSame(self::X, $jwk['x']);
        self::assertSame(self::D, $jwk['d']);

        $reloaded = OkpPrivateKey::fromJwk($jwk);
        self::assertSame($jwk, $reloaded->toJwk());
    }

    public function testToJwkOmitsOptionalAttributesWhenAbsent(): void
    {
        $jwk = self::jwk();
        unset($jwk['kid']);

        self::assertSame(['kty', 'alg', 'crv', 'x', 'd'], array_keys(OkpPrivateKey::fromJwk($jwk)->toJwk()));
    }

    public function testToJwkIncludesKeyOps(): void
    {
        $jwk = self::jwk() + ['key_ops' => ['sign']];
        self::assertSame(['sign'], OkpPrivateKey::fromJwk($jwk)->toJwk()['key_ops']);
    }

    public function testToPublicKeyDropsPrivateSeed(): void
    {
        $priv = OkpPrivateKey::fromJwk(self::jwk());
        $pub = $priv->toPublicKey();

        self::assertArrayNotHasKey('d', $pub->toJwk());
        self::assertSame(self::X, $pub->toJwk()['x']);
    }
}
