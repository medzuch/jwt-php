<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwt;

use DateInterval;
use DateTimeImmutable;
use LogicException;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Primitives\Json;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(JwtBuilder::class)]
final class JwtBuilderTest extends TestCase
{
    public function testHappyPathRoundTrip(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');

        $jwt = JwtBuilder::create($clock)
            ->issuer('https://issuer.example')
            ->subject('user-1')
            ->audience('https://api.example')
            ->expiresIn(new DateInterval('PT15M'))
            ->notBeforeNow()
            ->issuedAtNow()
            ->jwtId('id-1')
            ->type('at+jwt')
            ->withClaim('scope', 'read write')
            ->withHeader('kid', 'k1')
            ->signWith(new Hs256(), $key)
            ->build();

        $parsed = CompactSerializer::deserialize($jwt->value);
        $claims = Json::decode($parsed->payload);

        self::assertSame('HS256', $parsed->header['alg']);
        self::assertSame('at+jwt', $parsed->header['typ']);
        self::assertSame('k1', $parsed->header['kid']);
        self::assertSame('https://issuer.example', $claims['iss']);
        self::assertSame('user-1', $claims['sub']);
        self::assertSame('https://api.example', $claims['aud']);
        self::assertSame('read write', $claims['scope']);
        self::assertSame($clock->now()->getTimestamp(), $claims['iat']);
        self::assertSame($clock->now()->getTimestamp(), $claims['nbf']);
        self::assertSame($clock->now()->add(new DateInterval('PT15M'))->getTimestamp(), $claims['exp']);
    }

    public function testAudienceAcceptsList(): void
    {
        $jwt = JwtBuilder::create()
            ->audience(['a', 'b'])
            ->signWith(new Hs256(), HmacKey::fromBinary(random_bytes(32), 'HS256'))
            ->build();

        $claims = Json::decode(CompactSerializer::deserialize($jwt->value)->payload);

        self::assertSame(['a', 'b'], $claims['aud']);
    }

    public function testExpiresAtAcceptsAbsoluteInstant(): void
    {
        $when = new DateTimeImmutable('@1300819380');

        $jwt = JwtBuilder::create()
            ->expiresAt($when)
            ->signWith(new Hs256(), HmacKey::fromBinary(random_bytes(32), 'HS256'))
            ->build();

        $claims = Json::decode(CompactSerializer::deserialize($jwt->value)->payload);

        self::assertSame(1_300_819_380, $claims['exp']);
    }

    public function testBuildWithoutSignWithThrows(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/signWith/');

        JwtBuilder::create()->subject('x')->build();
    }

    public function testRegisteredClaimViaWithClaimIsRefused(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/sub\(\).*registered claim "sub"/');

        JwtBuilder::create()->withClaim('sub', 'user-1');
    }

    public function testReservedHeaderAlgIsRefused(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"alg".*reserved/');

        JwtBuilder::create()->withHeader('alg', 'none');
    }

    public function testReservedHeaderB64IsRefused(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"b64".*reserved/');

        JwtBuilder::create()->withHeader('b64', false);
    }

    public function testBuilderIsImmutable(): void
    {
        $a = JwtBuilder::create();
        $b = $a->subject('user-1');

        // Different instance, original untouched.
        self::assertNotSame($a, $b);

        $jwtA = $a->signWith(new Hs256(), HmacKey::fromBinary(random_bytes(32), 'HS256'))->build();
        $claimsA = Json::decode(CompactSerializer::deserialize($jwtA->value)->payload);

        self::assertArrayNotHasKey('sub', $claimsA);
    }

    public function testEmptyClaimsProduceEmptyJsonObject(): void
    {
        $jwt = JwtBuilder::create()
            ->signWith(new Hs256(), HmacKey::fromBinary(random_bytes(32), 'HS256'))
            ->build();

        $parsed = CompactSerializer::deserialize($jwt->value);

        // The payload must be a JSON object even when empty (RFC 7519 §3.1).
        self::assertSame('{}', $parsed->payload);
    }
}
