<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HmacKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class HmacKeyTest extends TestCase
{
    public function testFromBinaryAcceptsExactMinimumLength(): void
    {
        $key = HmacKey::fromBinary(str_repeat("\x00", 32), 'HS256');

        self::assertSame('HS256', $key->alg());
        self::assertSame(32, strlen($key->bytes()));
    }

    /** @param int<0,128> $bytes */
    #[DataProvider('belowMinimumProvider')]
    public function testFromBinaryRejectsBelowMinimum(string $alg, int $bytes): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/RFC 8725 §3\.5/');

        HmacKey::fromBinary(str_repeat("\x00", $bytes), $alg);
    }

    /** @return iterable<string, array{string, int<0,128>}> */
    public static function belowMinimumProvider(): iterable
    {
        yield 'HS256 with 31 bytes' => ['HS256', 31];
        yield 'HS384 with 47 bytes' => ['HS384', 47];
        yield 'HS512 with 63 bytes' => ['HS512', 63];
        yield 'HS256 with 1 byte' => ['HS256', 1];
    }

    public function testFromBinaryAcceptsLongerThanMinimum(): void
    {
        $key = HmacKey::fromBinary(random_bytes(128), 'HS256');

        self::assertSame(128, strlen($key->bytes()));
    }

    public function testFromBinaryRejectsUnknownAlgorithm(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/supports HS256\/HS384\/HS512/');

        HmacKey::fromBinary(random_bytes(64), 'PS256');
    }

    public function testCarriesOptionalAttributes(): void
    {
        $key = HmacKey::fromBinary(
            random_bytes(32),
            'HS256',
            kid: 'k-1',
            use: KeyUse::Sig,
        );

        self::assertSame('k-1', $key->kid());
        self::assertSame(KeyUse::Sig, $key->use());
        self::assertNull($key->keyOps());
    }

    public function testKeyOpsAndUseAreMutuallyExclusive(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/RFC 7517 §4\.3/');

        HmacKey::fromBinary(
            random_bytes(32),
            'HS256',
            use: KeyUse::Sig,
            keyOps: ['sign'],
        );
    }

    public function testEmptyKeyOpsIsRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/key_ops.*non-empty/');

        HmacKey::fromBinary(random_bytes(32), 'HS256', keyOps: []);
    }

    public function testToJwkRoundTrip(): void
    {
        $bytes = random_bytes(32);
        $original = HmacKey::fromBinary($bytes, 'HS256', kid: 'k1', use: KeyUse::Sig);

        $jwk = $original->toJwk();

        self::assertSame('oct', $jwk['kty']);
        self::assertSame('HS256', $jwk['alg']);
        self::assertSame('k1', $jwk['kid']);
        self::assertSame('sig', $jwk['use']);
        self::assertSame(Base64Url::encode($bytes), $jwk['k']);

        $reloaded = HmacKey::fromJwk($jwk);

        self::assertSame($bytes, $reloaded->bytes());
        self::assertSame('HS256', $reloaded->alg());
        self::assertSame('k1', $reloaded->kid());
        self::assertSame(KeyUse::Sig, $reloaded->use());
    }

    public function testToJwkOmitsOptionalAttributesWhenAbsent(): void
    {
        $jwk = HmacKey::fromBinary(random_bytes(32), 'HS256')->toJwk();

        self::assertSame(['kty', 'alg', 'k'], array_keys($jwk));
    }

    public function testFromJwkRequiresAlg(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/missing required "alg"/');

        HmacKey::fromJwk(['kty' => 'oct', 'k' => Base64Url::encode(random_bytes(32))]);
    }

    public function testFromJwkRequiresK(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/missing required "k"/');

        HmacKey::fromJwk(['kty' => 'oct', 'alg' => 'HS256']);
    }

    public function testFromJwkRejectsInvalidBase64(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        HmacKey::fromJwk(['kty' => 'oct', 'alg' => 'HS256', 'k' => 'has spaces and = padding']);
    }

    public function testFromJwkRejectsEmptyDecodedKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/empty/');

        HmacKey::fromJwk(['kty' => 'oct', 'alg' => 'HS256', 'k' => '']);
    }

    public function testFromJwkRejectsInvalidUse(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/use.*sig.*enc/');

        HmacKey::fromJwk([
            'kty' => 'oct',
            'alg' => 'HS256',
            'k' => Base64Url::encode(random_bytes(32)),
            'use' => 'authentication',
        ]);
    }

    public function testAssertAlgorithmAcceptsBoundAlgorithm(): void
    {
        $this->expectNotToPerformAssertions();

        HmacKey::fromBinary(random_bytes(32), 'HS256')->assertAlgorithm('HS256');
    }

    public function testAssertAlgorithmRejectsOtherAlgorithm(): void
    {
        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/RFC 8725 §3\.1/');

        HmacKey::fromBinary(random_bytes(32), 'HS256')->assertAlgorithm('HS384');
    }

    public function testFromJwkRejectsWrongKty(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/requires kty "oct".*"RSA"/');

        HmacKey::fromJwk([
            'kty' => 'RSA',
            'alg' => 'HS256',
            'k' => Base64Url::encode(random_bytes(32)),
        ]);
    }

    public function testFromJwkRequiresKty(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/missing required "kty"/');

        HmacKey::fromJwk(['alg' => 'HS256', 'k' => Base64Url::encode(random_bytes(32))]);
    }

    public function testFromBinaryRejectsEmptyKid(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/kid.*empty/');

        HmacKey::fromBinary(random_bytes(32), 'HS256', kid: '');
    }

    public function testAllowsOperationDefaultsToUnrestricted(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        self::assertTrue($key->allowsOperation('sign'));
        self::assertTrue($key->allowsOperation('verify'));
        self::assertTrue($key->allowsOperation('encrypt'));
    }

    public function testAllowsOperationHonoursUseSig(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', use: KeyUse::Sig);

        self::assertTrue($key->allowsOperation('sign'));
        self::assertTrue($key->allowsOperation('verify'));
        self::assertFalse($key->allowsOperation('encrypt'));
    }

    public function testAllowsOperationHonoursUseEnc(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', use: KeyUse::Enc);

        self::assertFalse($key->allowsOperation('sign'));
        self::assertTrue($key->allowsOperation('encrypt'));
        self::assertTrue($key->allowsOperation('decrypt'));
    }

    public function testAllowsOperationHonoursKeyOps(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', keyOps: ['sign']);

        self::assertTrue($key->allowsOperation('sign'));
        self::assertFalse($key->allowsOperation('verify'));
    }

    public function testFromJwkAcceptsKeyOpsArray(): void
    {
        $jwk = [
            'kty' => 'oct',
            'alg' => 'HS256',
            'k' => Base64Url::encode(random_bytes(32)),
            'key_ops' => ['sign', 'verify'],
        ];

        $key = HmacKey::fromJwk($jwk);

        self::assertSame(['sign', 'verify'], $key->keyOps());
    }

    public function testFromJwkRejectsNonListKeyOps(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/key_ops.*array/');

        HmacKey::fromJwk([
            'kty' => 'oct',
            'alg' => 'HS256',
            'k' => Base64Url::encode(random_bytes(32)),
            'key_ops' => ['x' => 'sign'],
        ]);
    }

    public function testFromJwkRejectsNonStringKeyOpsEntry(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/key_ops.*non-empty/');

        HmacKey::fromJwk([
            'kty' => 'oct',
            'alg' => 'HS256',
            'k' => Base64Url::encode(random_bytes(32)),
            'key_ops' => ['sign', 42],
        ]);
    }
}
