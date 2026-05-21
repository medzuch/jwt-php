<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jws;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\ParsedJws;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\Utf8;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CompactSerializer::class)]
#[CoversClass(CompactJws::class)]
#[CoversClass(ParsedJws::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(Json::class)]
#[UsesClass(Utf8::class)]
final class CompactSerializerTest extends TestCase
{
    public function testSerializeProducesThreeDotSeparatedSegments(): void
    {
        $jws = CompactSerializer::serialize(
            ['alg' => 'HS256', 'kid' => 'k1'],
            'payload-bytes',
            "\x01\x02\x03",
        );

        $segments = explode('.', $jws->value);

        self::assertCount(3, $segments);
        self::assertNotSame('', $segments[0]);
        self::assertSame(Base64Url::encode('payload-bytes'), $segments[1]);
        self::assertSame(Base64Url::encode("\x01\x02\x03"), $segments[2]);
    }

    public function testRoundTrip(): void
    {
        $header = ['alg' => 'HS256', 'kid' => 'k1', 'typ' => 'JWT'];
        $payload = '{"sub":"user-1"}';
        $signature = "\xff\xee\xdd\xcc";

        $jws = CompactSerializer::serialize($header, $payload, $signature);
        $parsed = CompactSerializer::deserialize($jws->value);

        self::assertSame($header, $parsed->header);
        self::assertSame($payload, $parsed->payload);
        self::assertSame($signature, $parsed->signature);
        self::assertSame($jws->value, $parsed->encodedHeader . '.' . $parsed->encodedPayload . '.' . $parsed->encodedSignature);
    }

    public function testSigningInputMatchesSegmentJoin(): void
    {
        $jws = CompactSerializer::serialize(['alg' => 'HS256'], 'p', 's');
        $parsed = CompactSerializer::deserialize($jws->value);

        self::assertSame($parsed->encodedHeader . '.' . $parsed->encodedPayload, $parsed->signingInput());
    }

    public function testCompactJwsIsStringable(): void
    {
        $jws = new CompactJws('a.b.c');

        self::assertSame('a.b.c', (string) $jws);
        self::assertSame('a.b.c', $jws->value);
    }

    public function testDeserializeRejectsEmptyString(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/empty/');

        CompactSerializer::deserialize('');
    }

    public function testDeserializeRejectsTwoSegments(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/exactly 3.*got 2/');

        CompactSerializer::deserialize('a.b');
    }

    public function testDeserializeRejectsFourSegments(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/exactly 3.*got 4/');

        CompactSerializer::deserialize('a.b.c.d');
    }

    public function testDeserializeRejectsEmptyHeaderSegment(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/header segment is empty/');

        CompactSerializer::deserialize('.payload.signature');
    }

    public function testDeserializeRejectsEmptySignatureSegment(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/signature segment is empty/');

        $encodedHeader = Base64Url::encode('{"alg":"HS256"}');
        CompactSerializer::deserialize($encodedHeader . '.payload.');
    }

    public function testDeserializeRejectsNonBase64UrlHeader(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        CompactSerializer::deserialize('not base64!.cGF5.c2ln');
    }

    public function testDeserializeRejectsHeaderThatIsNotJsonObject(): void
    {
        $this->expectException(MalformedJwtException::class);

        $encodedHeader = Base64Url::encode('"a string"');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeRejectsHeaderMissingAlg(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/missing required "alg"/');

        $encodedHeader = Base64Url::encode('{"kid":"k1"}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeRejectsNonStringAlg(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"alg".*non-empty string/');

        $encodedHeader = Base64Url::encode('{"alg":42}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeRejectsEmptyAlg(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"alg".*non-empty string/');

        $encodedHeader = Base64Url::encode('{"alg":""}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeRejectsNonStringTyp(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"typ".*string/');

        $encodedHeader = Base64Url::encode('{"alg":"HS256","typ":42}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    /**
     * Regression: an explicit JSON `null` for an optional header parameter
     * must be rejected as a malformed shape, not silently treated as if
     * the parameter were absent. `isset` would have collapsed `null` into
     * "key not present"; the shape guards use `array_key_exists` instead.
     */
    public function testDeserializeRejectsExplicitNullTyp(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"typ".*string/');

        $encodedHeader = Base64Url::encode('{"alg":"HS256","typ":null}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeRejectsExplicitNullCty(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"cty".*string/');

        $encodedHeader = Base64Url::encode('{"alg":"HS256","cty":null}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeRejectsExplicitNullKid(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"kid".*string/');

        $encodedHeader = Base64Url::encode('{"alg":"HS256","kid":null}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeRejectsExplicitNullCrit(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"crit".*list of strings/');

        $encodedHeader = Base64Url::encode('{"alg":"HS256","crit":null}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeRejectsNonStringKid(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"kid".*string/');

        $encodedHeader = Base64Url::encode('{"alg":"HS256","kid":42}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeRejectsCritNotAList(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"crit".*list of strings/');

        $encodedHeader = Base64Url::encode('{"alg":"HS256","crit":"b64"}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeRejectsCritWithNonStringEntry(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"crit".*list of strings/');

        $encodedHeader = Base64Url::encode('{"alg":"HS256","crit":["b64",42]}');
        CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');
    }

    public function testDeserializeAcceptsValidCritShape(): void
    {
        // Structural acceptance only — Verifier separately refuses crit
        // because Phase 1 understands no extensions.
        $encodedHeader = Base64Url::encode('{"alg":"HS256","crit":["b64"]}');
        $parsed = CompactSerializer::deserialize($encodedHeader . '.cGF5.c2ln');

        self::assertSame(['b64'], $parsed->header['crit']);
    }
}
