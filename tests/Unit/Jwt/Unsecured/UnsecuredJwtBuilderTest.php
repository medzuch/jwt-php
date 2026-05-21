<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwt\Unsecured;

use LogicException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jwt\Unsecured\UnsecuredJwtBuilder;
use Medzuch\Jwt\Primitives\FrozenClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(UnsecuredJwtBuilder::class)]
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
}
