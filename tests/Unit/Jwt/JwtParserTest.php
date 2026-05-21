<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwt;

use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(JwtParser::class)]
final class JwtParserTest extends TestCase
{
    public function testParseExposesHeaderAndUnverifiedClaims(): void
    {
        $jwt = JwtBuilder::create()
            ->issuer('https://issuer.example')
            ->subject('user-1')
            ->withHeader('kid', 'k1')
            ->signWith(new Hs256(), HmacKey::fromBinary(random_bytes(32), 'HS256'))
            ->build();

        $parsed = JwtParser::parse($jwt->value);

        self::assertSame('HS256', $parsed->header->algorithm());
        self::assertSame('k1', $parsed->header->keyId());
        self::assertSame('https://issuer.example', $parsed->unverifiedClaims->issuer());
        self::assertSame('user-1', $parsed->unverifiedClaims->subject());

        // The raw ParsedJws is preserved for the Validator.
        self::assertSame($jwt->value, $parsed->jws->encodedHeader . '.' . $parsed->jws->encodedPayload . '.' . $parsed->jws->encodedSignature);
    }

    public function testParseRefusesB64HeaderInJwtLayer(): void
    {
        // Build a JWS with `b64` in the header, bypassing the JwtBuilder
        // (which refuses it anyway). The parser must refuse it at the JWT
        // boundary per RFC 7797 §7.
        $jws = CompactSerializer::serialize(
            ['alg' => 'HS256', 'b64' => false],
            '{"sub":"x"}',
            "\x00",
        );

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"b64".*RFC 7797/');

        JwtParser::parse($jws->value);
    }

    public function testParseRefusesNonObjectPayload(): void
    {
        $encodedHeader = Base64Url::encode('{"alg":"HS256"}');
        $encodedPayload = Base64Url::encode('"a string"');
        $encodedSig = Base64Url::encode("\x00");

        $this->expectException(\Medzuch\Jwt\Exception\MalformedJwtException::class);

        JwtParser::parse($encodedHeader . '.' . $encodedPayload . '.' . $encodedSig);
    }

    public function testParsePropagatesMalformedCompactForm(): void
    {
        $this->expectException(\Medzuch\Jwt\Exception\MalformedJwtException::class);

        JwtParser::parse('not-a-compact-jws');
    }

    public function testParseDoesNotVerifySignature(): void
    {
        // The parser is purely structural: it does not detect a tampered
        // signature. The Validator does.
        $jwt = JwtBuilder::create()
            ->subject('user-1')
            ->signWith(new Hs256(), HmacKey::fromBinary(random_bytes(32), 'HS256'))
            ->build();

        [$h, $p] = explode('.', $jwt->value);
        $tampered = $h . '.' . $p . '.' . Base64Url::encode('garbage');

        $parsed = JwtParser::parse($tampered);

        self::assertSame('user-1', $parsed->unverifiedClaims->subject());
    }

    public function testEmptyClaimsPayloadParses(): void
    {
        $jwt = JwtBuilder::create()
            ->signWith(new Hs256(), HmacKey::fromBinary(random_bytes(32), 'HS256'))
            ->build();

        $parsed = JwtParser::parse($jwt->value);

        self::assertSame([], $parsed->unverifiedClaims->all());
    }

    public function testParseConsumesArbitraryPayload(): void
    {
        // Sanity: the parser doesn't choke on a payload that happens to
        // be valid JSON object with non-registered keys.
        $payload = Json::encode(['custom-1' => 'a', 'custom-2' => ['nested' => 1]]);
        $jws = CompactSerializer::serialize(['alg' => 'HS256'], $payload, "\x00");

        $parsed = JwtParser::parse($jws->value);

        self::assertSame('a', $parsed->unverifiedClaims->get('custom-1'));
    }
}
