<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\OkpKey;
use Medzuch\Jwt\Key\OkpPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OkpPublicKey::class)]
#[CoversClass(OkpKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class OkpPublicKeyTest extends TestCase
{
    /**
     * RFC 8037 §A.1 — Ed25519 public key.
     */
    private const X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';

    /** @return array<string, mixed> */
    private static function jwk(): array
    {
        return [
            'kty' => 'OKP',
            'alg' => 'EdDSA',
            'crv' => 'Ed25519',
            'kid' => 'k-ed',
            'x' => self::X,
        ];
    }

    public function testFromJwkLoadsPublicKey(): void
    {
        $key = OkpPublicKey::fromJwk(self::jwk());

        self::assertSame('EdDSA', $key->alg());
        self::assertSame('Ed25519', $key->curve());
        self::assertSame('k-ed', $key->kid());
        self::assertSame(32, strlen($key->publicKeyBytes()));
    }

    public function testFromJwkRejectsPrivateJwk(): void
    {
        $jwk = self::jwk();
        $jwk['d'] = Base64Url::encode(str_repeat("\x01", 32));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/OkpPrivateKey/');

        OkpPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsWrongKty(): void
    {
        $jwk = self::jwk();
        $jwk['kty'] = 'EC';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/requires kty "OKP".*"EC"/');

        OkpPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsWrongCurve(): void
    {
        $jwk = self::jwk();
        $jwk['crv'] = 'Ed448';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/supports crv "Ed25519".*"Ed448"/');

        OkpPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsWrongAlgorithm(): void
    {
        $jwk = self::jwk();
        $jwk['alg'] = 'ES256';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/supports alg "EdDSA".*"ES256"/');

        OkpPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsWrongCoordinateLength(): void
    {
        $jwk = self::jwk();
        $jwk['x'] = Base64Url::encode(str_repeat("\x01", 31));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"x" must be 32 bytes for Ed25519, got 31/');

        OkpPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRejectsInvalidBase64InX(): void
    {
        $jwk = self::jwk();
        $jwk['x'] = 'has spaces';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        OkpPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRequiresX(): void
    {
        $jwk = self::jwk();
        unset($jwk['x']);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"x"/');

        OkpPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRequiresCrv(): void
    {
        $jwk = self::jwk();
        unset($jwk['crv']);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"crv"/');

        OkpPublicKey::fromJwk($jwk);
    }

    public function testFromJwkRequiresAlg(): void
    {
        $jwk = self::jwk();
        unset($jwk['alg']);

        $this->expectException(InvalidKeyException::class);

        OkpPublicKey::fromJwk($jwk);
    }

    public function testToJwkRoundTrip(): void
    {
        $jwk = OkpPublicKey::fromJwk(self::jwk())->toJwk();

        self::assertSame('OKP', $jwk['kty']);
        self::assertSame('EdDSA', $jwk['alg']);
        self::assertSame('Ed25519', $jwk['crv']);
        self::assertSame(self::X, $jwk['x']);
        self::assertArrayNotHasKey('d', $jwk);

        $reloaded = OkpPublicKey::fromJwk($jwk);
        self::assertSame($jwk, $reloaded->toJwk());
    }

    public function testToJwkOmitsOptionalAttributesWhenAbsent(): void
    {
        $jwk = self::jwk();
        unset($jwk['kid']);
        $loaded = OkpPublicKey::fromJwk($jwk);

        self::assertSame(['kty', 'alg', 'crv', 'x'], array_keys($loaded->toJwk()));
    }

    public function testToJwkIncludesUseAndKeyOps(): void
    {
        $jwk = self::jwk() + ['use' => 'sig'];
        self::assertSame('sig', OkpPublicKey::fromJwk($jwk)->toJwk()['use']);

        $jwk = self::jwk() + ['key_ops' => ['verify']];
        self::assertSame(['verify'], OkpPublicKey::fromJwk($jwk)->toJwk()['key_ops']);
    }

    public function testCurveAccessor(): void
    {
        self::assertSame('Ed25519', OkpPublicKey::fromJwk(self::jwk())->curve());
    }
}
