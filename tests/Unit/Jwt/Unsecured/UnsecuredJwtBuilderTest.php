<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwt\Unsecured;

use DateInterval;
use DateTimeImmutable;
use LogicException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jwt\Unsecured\UnsecuredJwtBuilder;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\SystemClock;
use Medzuch\Jwt\Primitives\Utf8;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(UnsecuredJwtBuilder::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(CompactJws::class)]
#[UsesClass(CompactSerializer::class)]
#[UsesClass(FrozenClock::class)]
#[UsesClass(Json::class)]
#[UsesClass(SystemClock::class)]
#[UsesClass(Utf8::class)]
final class UnsecuredJwtBuilderTest extends TestCase
{
    public function testBuildProducesAlgNoneWithEmptySignatureSegment(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');

        $jwt = UnsecuredJwtBuilder::create($now)
            ->subject('user-1')
            ->build();

        $segments = explode('.', $jwt->value);

        self::assertCount(3, $segments);
        self::assertNotSame('', $segments[0]);
        self::assertNotSame('', $segments[1]);
        self::assertSame('', $segments[2], 'alg:none tokens must have an empty signature segment');
    }

    public function testCompactSerializerRefusesToParseUnsecuredOutput(): void
    {
        // The whole point of the dedicated builder: round-tripping its
        // output back through the safe parser is impossible by design.
        $jwt = UnsecuredJwtBuilder::create()->subject('x')->build();

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/signature segment is empty/');

        CompactSerializer::deserialize($jwt->value);
    }

    public function testReservedHeadersRefused(): void
    {
        $this->expectException(InvalidHeaderException::class);

        UnsecuredJwtBuilder::create()->withHeader('alg', 'HS256');
    }

    public function testRegisteredClaimViaWithClaimRefused(): void
    {
        $this->expectException(LogicException::class);

        UnsecuredJwtBuilder::create()->withClaim('sub', 'user-1');
    }

    /** Mirrors the producer-side guard in {@see \Medzuch\Jwt\Jwt\JwtBuilder}. */
    public function testAudienceRefusesAssociativeArray(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/associative array.*RFC 7519 §4\.1\.3/');

        /** @phpstan-ignore-next-line argument.type — testing runtime guard */
        UnsecuredJwtBuilder::create()->audience(['tenant' => 'https://api.example']);
    }

    public function testAudienceRefusesNonStringEntries(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/list entries must all be strings/');

        /** @phpstan-ignore-next-line argument.type — testing runtime guard */
        UnsecuredJwtBuilder::create()->audience(['ok', 42]);
    }

    public function testEmptyClaimsEmitsJsonObject(): void
    {
        $jwt = UnsecuredJwtBuilder::create()->build();

        $segments = explode('.', $jwt->value);
        $payloadEncoded = $segments[1];

        // Decode and confirm it's the JSON object literal, not a JSON array.
        $payload = \Medzuch\Jwt\Primitives\Base64Url::decode($payloadEncoded);

        self::assertSame('{}', $payload);
    }

    public function testCustomHeaderPassesThrough(): void
    {
        $jwt = UnsecuredJwtBuilder::create()
            ->withHeader('custom', 'value')
            ->subject('x')
            ->build();

        $segments = explode('.', $jwt->value);
        $header = json_decode(\Medzuch\Jwt\Primitives\Base64Url::decode($segments[0]), true);

        self::assertIsArray($header);
        self::assertSame('none', $header['alg']);
        self::assertSame('value', $header['custom']);
    }

    public function testAllRegisteredClaimSettersAppearInPayload(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $exp = new DateTimeImmutable('@1300819380');
        $nbf = new DateTimeImmutable('@1300819000');
        $iat = new DateTimeImmutable('@1300818000');

        $jwt = UnsecuredJwtBuilder::create($clock)
            ->issuer('https://issuer.example')
            ->subject('user-1')
            ->audience(['a', 'b'])
            ->expiresAt($exp)
            ->notBefore($nbf)
            ->issuedAt($iat)
            ->jwtId('id-1')
            ->type('at+jwt')
            ->build();

        $segments = explode('.', $jwt->value);
        $claims = Json::decode(Base64Url::decode($segments[1]));
        $header = Json::decode(Base64Url::decode($segments[0]));

        self::assertSame('https://issuer.example', $claims['iss']);
        self::assertSame('user-1', $claims['sub']);
        self::assertSame(['a', 'b'], $claims['aud']);
        self::assertSame(1_300_819_380, $claims['exp']);
        self::assertSame(1_300_819_000, $claims['nbf']);
        self::assertSame(1_300_818_000, $claims['iat']);
        self::assertSame('id-1', $claims['jti']);
        self::assertSame('at+jwt', $header['typ']);
    }

    public function testClockDrivenSettersUseClockNow(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');

        $jwt = UnsecuredJwtBuilder::create($clock)
            ->expiresIn(new DateInterval('PT15M'))
            ->notBeforeNow()
            ->issuedAtNow()
            ->build();

        $claims = Json::decode(Base64Url::decode(explode('.', $jwt->value)[1]));

        $nowTs = $clock->now()->getTimestamp();
        self::assertSame($nowTs, $claims['iat']);
        self::assertSame($nowTs, $claims['nbf']);
        self::assertSame($nowTs + 900, $claims['exp']);
    }

    public function testWithClockReplacesClock(): void
    {
        $orig = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $replacement = FrozenClock::at('2030-01-01T00:00:00+00:00');

        $jwt = UnsecuredJwtBuilder::create($orig)
            ->withClock($replacement)
            ->issuedAtNow()
            ->build();

        $claims = Json::decode(Base64Url::decode(explode('.', $jwt->value)[1]));

        self::assertSame($replacement->now()->getTimestamp(), $claims['iat']);
    }

    public function testBuilderIsImmutable(): void
    {
        $a = UnsecuredJwtBuilder::create();
        $b = $a->subject('user-1');

        self::assertNotSame($a, $b);

        // Build the original — it must not contain 'sub'.
        $jwt = $a->build();
        $claims = Json::decode(Base64Url::decode(explode('.', $jwt->value)[1]));

        self::assertArrayNotHasKey('sub', $claims);
    }

    public function testReservedHeaderB64IsRefused(): void
    {
        $this->expectException(InvalidHeaderException::class);

        UnsecuredJwtBuilder::create()->withHeader('b64', false);
    }
}
