<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OctKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\Key::class)]
#[UsesClass(\Medzuch\Jwt\Key\SymmetricKey::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class OctKeyTest extends TestCase
{
    /** @return iterable<string, array{string, int}> */
    public static function algLengthProvider(): iterable
    {
        yield 'A128GCM' => ['A128GCM', 16];
        yield 'A192GCM' => ['A192GCM', 24];
        yield 'A256GCM' => ['A256GCM', 32];
        yield 'A128CBC-HS256' => ['A128CBC-HS256', 32];
        yield 'A192CBC-HS384' => ['A192CBC-HS384', 48];
        yield 'A256CBC-HS512' => ['A256CBC-HS512', 64];
    }

    #[DataProvider('algLengthProvider')]
    public function testFromBinaryAcceptsExactLength(string $alg, int $bytes): void
    {
        $key = OctKey::fromBinary(str_repeat("\x01", $bytes), $alg, kid: 'k1');

        self::assertSame($alg, $key->alg());
        self::assertSame('k1', $key->kid());
        self::assertSame($bytes, strlen($key->bytes()));
    }

    #[DataProvider('algLengthProvider')]
    public function testFromBinaryRejectsWrongLength(string $alg, int $bytes): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/must be exactly ' . $bytes . ' bytes/');

        OctKey::fromBinary(str_repeat("\x01", $bytes - 1), $alg);
    }

    public function testRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/OctKey supports/');

        // RSA-OAEP is an RSA key-encryption alg (and deferred, D-003); it is
        // never a symmetric `oct` binding.
        OctKey::fromBinary(str_repeat("\x01", 16), 'RSA-OAEP');
    }

    public function testRejectsSigningAlgorithm(): void
    {
        $this->expectException(InvalidKeyException::class);

        OctKey::fromBinary(str_repeat("\x01", 32), 'HS256');
    }

    public function testFromJwkRoundTrips(): void
    {
        $bytes = random_bytes(32);
        $jwk = [
            'kty' => 'oct',
            'alg' => 'A256GCM',
            'k' => Base64Url::encode($bytes),
            'kid' => 'enc-1',
            'use' => 'enc',
        ];

        $key = OctKey::fromJwk($jwk);

        self::assertSame($bytes, $key->bytes());
        self::assertSame('A256GCM', $key->alg());
        self::assertSame('enc-1', $key->kid());
        self::assertSame(KeyUse::Enc, $key->use());

        self::assertSame($jwk, $key->toJwk());
    }

    public function testFromJwkRejectsNonOctKty(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/requires kty "oct"/');

        OctKey::fromJwk(['kty' => 'RSA', 'alg' => 'A256GCM', 'k' => Base64Url::encode(random_bytes(32))]);
    }

    public function testFromJwkRejectsNonBase64UrlK(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        OctKey::fromJwk(['kty' => 'oct', 'alg' => 'A256GCM', 'k' => 'not base64!']);
    }

    public function testToJwkIncludesKeyOps(): void
    {
        $key = OctKey::fromBinary(random_bytes(16), 'A128GCM', keyOps: ['encrypt', 'decrypt']);

        self::assertSame(['encrypt', 'decrypt'], $key->toJwk()['key_ops']);
    }
}
