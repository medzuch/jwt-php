<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwt;

use DateInterval;
use DateTimeImmutable;
use LogicException;
use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Hs384;
use Medzuch\Jwt\Exception\ExpiredException;
use Medzuch\Jwt\Exception\InvalidAudienceException;
use Medzuch\Jwt\Exception\InvalidIssuerException;
use Medzuch\Jwt\Exception\InvalidSubjectException;
use Medzuch\Jwt\Exception\InvalidTypeException;
use Medzuch\Jwt\Exception\IssuedInFutureException;
use Medzuch\Jwt\Exception\MissingClaimException;
use Medzuch\Jwt\Exception\NotYetValidException;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\ParsedJws;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\Header;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\MediaType;
use Medzuch\Jwt\Jwt\ParsedJwt;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\ConstantTime;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\SystemClock;
use Medzuch\Jwt\Primitives\Utf8;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(\Medzuch\Jwt\Jwt\Validator::class)]
#[CoversClass(ValidatorBuilder::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(ClaimsSet::class)]
#[UsesClass(CompactJws::class)]
#[UsesClass(CompactSerializer::class)]
#[UsesClass(ConstantTime::class)]
#[UsesClass(FrozenClock::class)]
#[UsesClass(Header::class)]
#[UsesClass(HmacAlgorithm::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(Hs384::class)]
#[UsesClass(JwkSet::class)]
#[UsesClass(Json::class)]
#[UsesClass(JwtBuilder::class)]
#[UsesClass(JwtParser::class)]
#[UsesClass(Key::class)]
#[UsesClass(ParsedJws::class)]
#[UsesClass(ParsedJwt::class)]
#[UsesClass(Signer::class)]
#[UsesClass(StaticJwkSetResolver::class)]
#[UsesClass(SystemClock::class)]
#[UsesClass(Utf8::class)]
#[UsesClass(Verifier::class)]
final class ValidatorTest extends TestCase
{
    private const ISSUER = 'https://issuer.example';
    private const AUDIENCE = 'https://api.example';

    public function testTypeAndExpectTypeAcceptMediaTypeValueObject(): void
    {
        // MediaType::accessToken() and the literal string "at+jwt" are
        // interchangeable on both the producer and consumer sides.
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->issuer(self::ISSUER)
            ->subject('user-1')
            ->audience(self::AUDIENCE)
            ->expiresIn(new DateInterval('PT15M'))
            ->issuedAtNow()
            ->type(MediaType::accessToken())
            ->withHeader('kid', 'k1')
            ->signWith(new Hs256(), $key)
            ->build();

        $parsed = JwtParser::parse($jwt->value);
        self::assertSame('at+jwt', $parsed->header->type());

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectIssuer(self::ISSUER)
            ->expectAudience(self::AUDIENCE)
            ->expectType(MediaType::accessToken())
            ->requireClaims(['sub', 'exp', 'iat'])
            ->build();

        self::assertSame('user-1', $validator->validate($parsed)->subject());
    }

    public function testHappyPath(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->issuer(self::ISSUER)
            ->subject('user-1')
            ->audience(self::AUDIENCE)
            ->expiresIn(new DateInterval('PT15M'))
            ->issuedAtNow()
            ->type('at+jwt')
            ->withHeader('kid', 'k1')
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectIssuer(self::ISSUER)
            ->expectAudience(self::AUDIENCE)
            ->expectType('at+jwt')
            ->requireClaims(['sub', 'exp', 'iat'])
            ->build();

        $claims = $validator->validate(JwtParser::parse($jwt->value));

        self::assertSame('user-1', $claims->subject());
    }

    public function testExpired(): void
    {
        $issuedAt = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($issuedAt)
            ->subject('x')
            ->expiresIn(new DateInterval('PT1M'))
            ->signWith(new Hs256(), $key)
            ->build();

        $later = FrozenClock::at('2026-05-21T00:10:00+00:00');

        $this->expectException(ExpiredException::class);

        $this->buildValidator($key, $later)->validate(JwtParser::parse($jwt->value));
    }

    public function testNotYetValid(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $future = (new DateTimeImmutable('2026-05-21T00:10:00+00:00'));
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->notBefore($future)
            ->signWith(new Hs256(), $key)
            ->build();

        $this->expectException(NotYetValidException::class);

        $this->buildValidator($key, $now)->validate(JwtParser::parse($jwt->value));
    }

    public function testIssuedInFuture(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $future = (new DateTimeImmutable('2026-05-21T00:10:00+00:00'));
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->issuedAt($future)
            ->signWith(new Hs256(), $key)
            ->build();

        $this->expectException(IssuedInFutureException::class);

        $this->buildValidator($key, $now)->validate(JwtParser::parse($jwt->value));
    }

    public function testLeewayCoversBoundaryExpiry(): void
    {
        $issuedAt = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($issuedAt)
            ->subject('x')
            ->expiresIn(new DateInterval('PT1M')) // expires at +60s
            ->signWith(new Hs256(), $key)
            ->build();

        // Token expired 30s ago; 60s of leeway lets it through.
        $tooLate = FrozenClock::at('2026-05-21T00:01:30+00:00');

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($tooLate)
            ->withLeeway(new DateInterval('PT60S'))
            ->build();

        $claims = $validator->validate(JwtParser::parse($jwt->value));

        self::assertSame('x', $claims->subject());
    }

    public function testLeewayCeilingRefused(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/exceeds the hard ceiling/');

        ValidatorBuilder::create()->withLeeway(new DateInterval('PT10M'));
    }

    public function testNegativeLeewayRefused(): void
    {
        $interval = new DateInterval('PT1S');
        $interval->invert = 1;

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/non-negative/');

        ValidatorBuilder::create()->withLeeway($interval);
    }

    public function testIssuerMismatch(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->issuer('https://other.example')
            ->signWith(new Hs256(), $key)
            ->build();

        $this->expectException(InvalidIssuerException::class);

        $this->buildValidator($key, $now)
            ->validate(JwtParser::parse($jwt->value));
    }

    public function testIssuerAcceptsAnyOfList(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->issuer('https://b.example')
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectIssuer(['https://a.example', 'https://b.example'])
            ->build();

        $claims = $validator->validate(JwtParser::parse($jwt->value));

        self::assertSame('https://b.example', $claims->issuer());
    }

    public function testIssuerMissingWhenExpected(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->signWith(new Hs256(), $key)
            ->build();

        $this->expectException(InvalidIssuerException::class);
        $this->expectExceptionMessageMatches('/no "iss"/');

        $this->buildValidator($key, $now)->validate(JwtParser::parse($jwt->value));
    }

    public function testAudienceIntersection(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->issuer(self::ISSUER)
            ->audience(['https://api.example', 'https://other.example'])
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectIssuer(self::ISSUER)
            ->expectAudience('https://api.example')
            ->build();

        $claims = $validator->validate(JwtParser::parse($jwt->value));

        self::assertSame(['https://api.example', 'https://other.example'], $claims->audience());
    }

    public function testAudienceNoIntersection(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->issuer(self::ISSUER)
            ->subject('x')
            ->audience('https://wrong.example')
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectIssuer(self::ISSUER)
            ->expectAudience(self::AUDIENCE)
            ->build();

        $this->expectException(InvalidAudienceException::class);

        $validator->validate(JwtParser::parse($jwt->value));
    }

    /**
     * Regression: a token with an object-shaped `aud` claim was reaching
     * the validator and being treated as if it were a valid list whose
     * values matched the expected audience. ClaimsSet::audience() now
     * refuses any non-list array.
     */
    public function testAudienceRejectsObjectShapedAudClaim(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        // JwtBuilder's audience() only accepts string|list, so we go around
        // it via withClaim... but withClaim refuses 'aud' as a registered
        // claim. Build the JSON directly through the JWS layer to force
        // the malformed shape into the token.
        $signer = new \Medzuch\Jwt\Jws\Signer();
        $payload = '{"aud":{"tenant":"https://api.example"}}';
        $jws = $signer->sign(new Hs256(), [], $payload, $key);

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectAudience('https://api.example')
            ->build();

        $this->expectException(\Medzuch\Jwt\Exception\ClaimTypeException::class);

        $validator->validate(JwtParser::parse($jws->value));
    }

    public function testAudienceMissingWhenExpected(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->issuer(self::ISSUER)
            ->subject('x')
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectIssuer(self::ISSUER)
            ->expectAudience(self::AUDIENCE)
            ->build();

        $this->expectException(InvalidAudienceException::class);
        $this->expectExceptionMessageMatches('/no "aud"/');

        $validator->validate(JwtParser::parse($jwt->value));
    }

    public function testSubjectMismatch(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->issuer(self::ISSUER)
            ->subject('user-2')
            ->audience(self::AUDIENCE)
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectIssuer(self::ISSUER)
            ->expectAudience(self::AUDIENCE)
            ->expectSubject('user-1')
            ->build();

        $this->expectException(InvalidSubjectException::class);

        $validator->validate(JwtParser::parse($jwt->value));
    }

    public function testTypMismatch(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->type('id+jwt')
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectType('at+jwt')
            ->build();

        $this->expectException(InvalidTypeException::class);

        $validator->validate(JwtParser::parse($jwt->value));
    }

    public function testTypMissingWhenExpected(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectType('at+jwt')
            ->build();

        $this->expectException(InvalidTypeException::class);
        $this->expectExceptionMessageMatches('/required/');

        $validator->validate(JwtParser::parse($jwt->value));
    }

    public function testTypAcceptsMediaTypeShorthand(): void
    {
        // RFC 7515 §4.1.9: `application/at+jwt` and `at+jwt` are equivalent.
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->type('application/at+jwt')
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->expectType('at+jwt')
            ->build();

        $claims = $validator->validate(JwtParser::parse($jwt->value));

        self::assertSame('x', $claims->subject());
    }

    public function testRequiredClaimMissing(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->requireClaims(['scope'])
            ->build();

        $this->expectException(MissingClaimException::class);
        $this->expectExceptionMessageMatches('/"scope"/');

        $validator->validate(JwtParser::parse($jwt->value));
    }

    public function testCryptoFailurePropagates(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $signingKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $verifyingKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->signWith(new Hs256(), $signingKey)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($verifyingKey))
            ->withClock($now)
            ->build();

        $this->expectException(\Medzuch\Jwt\Exception\SignatureVerificationException::class);

        $validator->validate(JwtParser::parse($jwt->value));
    }

    public function testBuildWithoutAlgorithmsFails(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/expectAlgorithms/');

        ValidatorBuilder::create()->build();
    }

    public function testBuildWithoutKeysFails(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/withKeys/');

        ValidatorBuilder::create()->expectAlgorithms([new Hs256()])->build();
    }

    public function testAlgNotInExpectAlgorithmsRefused(): void
    {
        $now = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($now)
            ->subject('x')
            ->signWith(new Hs256(), $key)
            ->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs384()])
            ->withKeys(JwkSet::of($key))
            ->withClock($now)
            ->build();

        $this->expectException(\Medzuch\Jwt\Exception\AlgorithmNotAllowedException::class);

        $validator->validate(JwtParser::parse($jwt->value));
    }

    private function buildValidator(HmacKey $key, FrozenClock $clock): \Medzuch\Jwt\Jwt\Validator
    {
        return ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256()])
            ->withKeys(JwkSet::of($key))
            ->withClock($clock)
            ->expectIssuer(self::ISSUER)
            ->build();
    }
}
