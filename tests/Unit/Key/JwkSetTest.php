<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\JwkParser;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\RsaKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

use function random_bytes;

#[CoversClass(JwkSet::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(JwkParser::class)]
#[UsesClass(RsaPublicKey::class)]
#[UsesClass(RsaKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class JwkSetTest extends TestCase
{
    public function testFindByKidReturnsMatchingKey(): void
    {
        $a = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'a');
        $b = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'b');
        $set = JwkSet::of($a, $b);

        self::assertSame($a, $set->findByKid('a'));
        self::assertSame($b, $set->findByKid('b'));
        self::assertNull($set->findByKid('unknown'));
    }

    public function testFindByKidIgnoresKeysWithoutKid(): void
    {
        $noKid = HmacKey::fromBinary(random_bytes(32), 'HS256');
        $withKid = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k');
        $set = JwkSet::of($noKid, $withKid);

        self::assertSame($withKid, $set->findByKid('k'));
    }

    public function testFindForAlgorithmReturnsFirstMatch(): void
    {
        $hs = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'first');
        $hsSecond = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'second');
        $set = JwkSet::of($hs, $hsSecond);

        self::assertSame($hs, $set->findForAlgorithm('HS256'));
        self::assertNull($set->findForAlgorithm('HS384'));
    }

    public function testFromArrayParsesJwkSetDocument(): void
    {
        $bytes = random_bytes(32);
        $set = JwkSet::fromArray([
            ['kty' => 'oct', 'alg' => 'HS256', 'kid' => 'k1', 'k' => Base64Url::encode($bytes)],
            ['kty' => 'oct', 'alg' => 'HS384', 'kid' => 'k2', 'k' => Base64Url::encode(random_bytes(48))],
        ]);

        self::assertSame(2, $set->count());
        $k1 = $set->findByKid('k1');
        self::assertInstanceOf(HmacKey::class, $k1);
        self::assertSame($bytes, $k1->bytes());
    }

    public function testFromArrayRejectsNonListInput(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/JSON array/');

        // The signature accepts array<array-key, ...> so callers can give
        // associative arrays; the runtime guard then refuses them.
        JwkSet::fromArray(['k1' => ['kty' => 'oct', 'alg' => 'HS256', 'k' => 'AAAA']]);
    }

    public function testToArrayRoundTrip(): void
    {
        $bytes = random_bytes(32);
        $original = JwkSet::of(
            HmacKey::fromBinary($bytes, 'HS256', kid: 'k1'),
        );

        $arr = $original->toArray();
        self::assertCount(1, $arr['keys']);

        $reloaded = JwkSet::fromArray($arr['keys']);

        $reloadedKey = $reloaded->findByKid('k1');
        self::assertInstanceOf(HmacKey::class, $reloadedKey);
        self::assertSame($bytes, $reloadedKey->bytes());
    }

    public function testEmptySetHasZeroCountAndReturnsNullForLookups(): void
    {
        $set = JwkSet::of();

        self::assertSame(0, $set->count());
        self::assertSame([], $set->all());
        self::assertNull($set->findByKid('anything'));
        self::assertNull($set->findForAlgorithm('HS256'));
    }

    public function testAllReturnsTheUnderlyingList(): void
    {
        $a = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'a');
        $b = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'b');
        $set = JwkSet::of($a, $b);

        self::assertSame([$a, $b], $set->all());
    }
}
