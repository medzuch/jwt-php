<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Primitives\FrozenClock;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7519 §3.1 example, driven through the public JWT API. The compact
 * form is identical to RFC 7515 §A.1 (the JWT spec borrows the JWS
 * example); here we additionally exercise the JwtParser + Validator path.
 */
#[CoversNothing]
final class Rfc7519Section31Test extends TestCase
{
    private const COMPACT
        = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
        . '.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        . '.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    private const JWK_K = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

    public function testParserExposesTheVectorClaims(): void
    {
        $parsed = JwtParser::parse(self::COMPACT);

        self::assertSame('HS256', $parsed->header->algorithm());
        self::assertSame('JWT', $parsed->header->type());
        self::assertSame('joe', $parsed->unverifiedClaims->issuer());
        self::assertSame(1_300_819_380, $parsed->unverifiedClaims->expiresAt()?->getTimestamp());
        self::assertTrue($parsed->unverifiedClaims->getBool('http://example.com/is_root'));
    }

    public function testValidatorAcceptsTheRfcVector(): void
    {
        // Freeze the clock to a point inside the vector's validity window
        // (exp = 1300819380 = 2011-03-22T18:43:00Z).
        $clock = FrozenClock::at('2011-03-22T18:00:00+00:00');

        $key = HmacKey::fromJwk(['kty' => 'oct', 'alg' => 'HS256', 'k' => self::JWK_K]);

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($clock)
            ->expectIssuer('joe')
            ->build();

        $claims = $validator->validate(JwtParser::parse(self::COMPACT));

        self::assertSame('joe', $claims->issuer());
        self::assertTrue($claims->getBool('http://example.com/is_root'));
    }
}
