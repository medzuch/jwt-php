<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\JwkParser;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\RsaKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function random_bytes;

use const OPENSSL_KEYTYPE_RSA;

#[CoversClass(JwkParser::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(RsaPublicKey::class)]
#[UsesClass(RsaPrivateKey::class)]
#[UsesClass(RsaKey::class)]
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

    public function testRejectsUnknownKty(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"EC".*not supported/');

        JwkParser::parse(['kty' => 'EC', 'alg' => 'ES256']);
    }

    public function testRejectsMissingKty(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/missing required "kty"/');

        JwkParser::parse(['alg' => 'HS256']);
    }
}
