<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\EcKey;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\EcCurve;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\JwkParser;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\OkpKey;
use Medzuch\Jwt\Key\OkpPrivateKey;
use Medzuch\Jwt\Key\OkpPublicKey;
use Medzuch\Jwt\Key\RsaKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(JwkParser::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(RsaPublicKey::class)]
#[UsesClass(RsaPrivateKey::class)]
#[UsesClass(RsaKey::class)]
#[UsesClass(EcPublicKey::class)]
#[UsesClass(EcPrivateKey::class)]
#[UsesClass(EcKey::class)]
#[UsesClass(EcCurve::class)]
#[UsesClass(OkpPublicKey::class)]
#[UsesClass(OkpPrivateKey::class)]
#[UsesClass(OkpKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class JwkParserTest extends TestCase
{
    public function testParsesOctAsHmac(): void
    {
        $jwk = [
            'kty' => 'oct',
            'alg' => 'HS256',
            'k' => Base64Url::encode(random_bytes(32)),
        ];

        self::assertInstanceOf(HmacKey::class, JwkParser::parse($jwk));
    }

    public function testParsesRsaWithoutDAsPublic(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($resource);
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        $rsa = $details['rsa'];

        $jwk = [
            'kty' => 'RSA',
            'alg' => 'RS256',
            'n' => Base64Url::encode($rsa['n']),
            'e' => Base64Url::encode($rsa['e']),
        ];

        self::assertInstanceOf(RsaPublicKey::class, JwkParser::parse($jwk));
    }

    public function testParsesRsaWithDAsPrivate(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($resource);
        $privatePem = '';
        openssl_pkey_export($resource, $privatePem);

        $jwk = RsaPrivateKey::fromPem($privatePem, 'RS256')->toJwk();

        self::assertInstanceOf(RsaPrivateKey::class, JwkParser::parse($jwk));
    }

    public function testParsesEcWithoutDAsPublic(): void
    {
        $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($ec);
        $details = openssl_pkey_get_details($ec);
        self::assertIsArray($details);
        self::assertIsArray($details['ec']);
        self::assertIsString($details['ec']['x']);
        self::assertIsString($details['ec']['y']);

        $pad = static fn(string $b) => str_pad($b, 32, "\x00", STR_PAD_LEFT);
        $jwk = [
            'kty' => 'EC',
            'alg' => 'ES256',
            'crv' => 'P-256',
            'x' => Base64Url::encode($pad($details['ec']['x'])),
            'y' => Base64Url::encode($pad($details['ec']['y'])),
        ];

        self::assertInstanceOf(EcPublicKey::class, JwkParser::parse($jwk));
    }

    public function testParsesEcWithDAsPrivate(): void
    {
        $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($ec);
        $privatePem = '';
        openssl_pkey_export($ec, $privatePem);

        $jwk = EcPrivateKey::fromPem($privatePem, 'ES256')->toJwk();

        self::assertInstanceOf(EcPrivateKey::class, JwkParser::parse($jwk));
    }

    public function testParsesOkpWithoutDAsPublic(): void
    {
        $jwk = [
            'kty' => 'OKP',
            'alg' => 'EdDSA',
            'crv' => 'Ed25519',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ];

        self::assertInstanceOf(OkpPublicKey::class, JwkParser::parse($jwk));
    }

    public function testParsesOkpWithDAsPrivate(): void
    {
        $jwk = [
            'kty' => 'OKP',
            'alg' => 'EdDSA',
            'crv' => 'Ed25519',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
            'd' => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
        ];

        self::assertInstanceOf(OkpPrivateKey::class, JwkParser::parse($jwk));
    }

    public function testRejectsUnknownKty(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"BL".*not supported/');

        JwkParser::parse(['kty' => 'BL']);
    }

    public function testRejectsMissingKty(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/missing required "kty"/');

        JwkParser::parse(['alg' => 'HS256']);
    }
}
