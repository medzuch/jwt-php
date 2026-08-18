<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Profile;

use DateInterval;
use LogicException;
use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Diagnostics\SecurityLog;
use Medzuch\Jwt\Exception\ExpiredException;
use Medzuch\Jwt\Exception\InvalidAudienceException;
use Medzuch\Jwt\Exception\InvalidTypeException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Exception\MissingClaimException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
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
use Medzuch\Jwt\Primitives\Random;
use Medzuch\Jwt\Primitives\SystemClock;
use Medzuch\Jwt\Primitives\Utf8;
use Medzuch\Jwt\Profile\AccessTokenBuilder;
use Medzuch\Jwt\Profile\AccessTokenConsumer;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\Jwt\Profile\ProfileConsumer;
use Medzuch\Jwt\Tests\Support\SpyLogger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

#[CoversClass(AccessTokenProfile::class)]
#[CoversClass(AccessTokenBuilder::class)]
#[CoversClass(AccessTokenConsumer::class)]
#[CoversClass(ProfileConsumer::class)]
#[UsesClass(LogLevels::class)]
#[UsesClass(SecurityLog::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(ClaimsSet::class)]
#[UsesClass(CompactJws::class)]
#[UsesClass(CompactSerializer::class)]
#[UsesClass(\Medzuch\Jwt\Jws\Internal\B64Header::class)]
#[UsesClass(\Medzuch\Jwt\Jws\Internal\HeaderShape::class)]
#[UsesClass(ConstantTime::class)]
#[UsesClass(FrozenClock::class)]
#[UsesClass(Header::class)]
#[UsesClass(HmacAlgorithm::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(JwkSet::class)]
#[UsesClass(Json::class)]
#[UsesClass(JwtBuilder::class)]
#[UsesClass(JwtParser::class)]
#[UsesClass(Key::class)]
#[UsesClass(MediaType::class)]
#[UsesClass(ParsedJws::class)]
#[UsesClass(ParsedJwt::class)]
#[UsesClass(Random::class)]
#[UsesClass(Signer::class)]
#[UsesClass(StaticJwkSetResolver::class)]
#[UsesClass(SystemClock::class)]
#[UsesClass(Utf8::class)]
#[UsesClass(\Medzuch\Jwt\Jwt\Validator::class)]
#[UsesClass(ValidatorBuilder::class)]
#[UsesClass(Verifier::class)]
final class AccessTokenProfileTest extends TestCase
{
    private const ISSUER = 'https://issuer.example';
    private const AUDIENCE = 'https://api.example';
    private const CLIENT = 'web-app-1';

    public function testRoundTripAccessTokenIsAcceptedByConsumer(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::AUDIENCE)
            ->clientId(self::CLIENT)
            ->scope(['read', 'write'])
            ->expiresIn(new DateInterval('PT15M'))
            ->build();

        $claims = $this->consumer($key, $clock)->parse($jwt->value);

        self::assertSame('user-123', $claims->subject());
        self::assertSame(self::ISSUER, $claims->issuer());
        self::assertSame([self::AUDIENCE], $claims->audience());
        self::assertSame(self::CLIENT, $claims->getString('client_id'));
    }

    public function testIssueStampsAtJwtTypeAndAutoClaims(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->minimalToken($key, $clock);
        $parsed = JwtParser::parse($jwt->value);

        self::assertSame('at+jwt', $parsed->header->type());
        self::assertSame('k1', $parsed->header->keyId());
        self::assertNotNull($parsed->unverifiedClaims->issuedAt());
        // 16 random bytes, hex-encoded.
        self::assertSame(32, strlen((string) $parsed->unverifiedClaims->jwtId()));
    }

    public function testIssueOmitsKidHeaderWhenKeyHasNoKid(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256'); // no kid

        $parsed = JwtParser::parse($this->minimalToken($key, $clock)->value);

        self::assertFalse($parsed->header->has('kid'));
    }

    public function testScopeIsSpaceDelimitedString(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::AUDIENCE)
            ->clientId(self::CLIENT)
            ->scope(['read', 'write', 'admin'])
            ->expiresIn(new DateInterval('PT15M'))
            ->build();

        $claims = JwtParser::parse($jwt->value)->unverifiedClaims;

        self::assertSame('read write admin', $claims->getString('scope'));
    }

    public function testJwtIdAndIssuedAtAreOverridable(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $issuedAt = new \DateTimeImmutable('2026-05-20T12:00:00+00:00');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::AUDIENCE)
            ->clientId(self::CLIENT)
            ->expiresIn(new DateInterval('PT15M'))
            ->jwtId('fixed-jti')
            ->issuedAt($issuedAt)
            ->build();

        $claims = JwtParser::parse($jwt->value)->unverifiedClaims;

        self::assertSame('fixed-jti', $claims->jwtId());
        self::assertSame($issuedAt->getTimestamp(), $claims->issuedAt()?->getTimestamp());
    }

    public function testConsumerRejectsMissingClientId(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        // A well-formed at+jwt that simply omits client_id.
        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::AUDIENCE)
            ->expiresIn(new DateInterval('PT15M'))
            ->build();

        $this->expectException(MissingClaimException::class);
        $this->expectExceptionMessageMatches('/client_id/');

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testConsumerRejectsWrongType(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        // Same claims, but typ id+jwt instead of at+jwt.
        $jwt = JwtBuilder::create($clock)
            ->issuer(self::ISSUER)
            ->subject('user-123')
            ->audience(self::AUDIENCE)
            ->withClaim('client_id', self::CLIENT)
            ->issuedAtNow()
            ->jwtId('j1')
            ->expiresIn(new DateInterval('PT15M'))
            ->type(MediaType::idToken())
            ->signWith(new Hs256(), $key)
            ->build();

        $this->expectException(InvalidTypeException::class);

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testConsumerRejectsWrongAudience(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience('https://other.example')
            ->clientId(self::CLIENT)
            ->expiresIn(new DateInterval('PT15M'))
            ->build();

        $this->expectException(InvalidAudienceException::class);

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testWithClaimAndWithHeaderPassThrough(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::AUDIENCE)
            ->clientId(self::CLIENT)
            ->authTime(new \DateTimeImmutable('2026-05-21T00:00:00+00:00'))
            ->expiresIn(new DateInterval('PT15M'))
            ->withClaim('tenant', 'acme')
            ->withHeader('cty', 'application/example')
            ->build();

        $parsed = JwtParser::parse($jwt->value);

        self::assertSame('acme', $parsed->unverifiedClaims->getString('tenant'));
        self::assertSame('application/example', $parsed->header->contentType());
        self::assertNotNull($parsed->unverifiedClaims->getInt('auth_time'));
    }

    public function testExpiresAtAndNotBeforePassThrough(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $exp = new \DateTimeImmutable('2026-05-21T00:30:00+00:00');
        $nbf = new \DateTimeImmutable('2026-05-21T00:00:00+00:00');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::AUDIENCE)
            ->clientId(self::CLIENT)
            ->notBefore($nbf)
            ->expiresAt($exp)
            ->build();

        $claims = $this->consumer($key, $clock)->parse($jwt->value);

        self::assertSame($exp->getTimestamp(), $claims->expiresAt()?->getTimestamp());
        self::assertSame($nbf->getTimestamp(), $claims->notBefore()?->getTimestamp());
    }

    public function testConsumerLogsAcceptedTokenWithProfileName(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $jwt = $this->minimalToken($key, $clock);

        $spy = new SpyLogger();
        $this->consumerWithLogger($key, $clock, $spy)->parse($jwt->value);

        self::assertSame(1, $spy->count(), 'one event for the whole parse — validator built without a logger');
        $record = $spy->last();
        self::assertSame(LogLevel::DEBUG, $record['level']);
        self::assertSame('JWT accepted', $record['message']);
        self::assertSame('access-token', $record['context']['profile']);
        self::assertSame('k1', $record['context']['kid']);
    }

    public function testConsumerLogsClaimRejectionWithProfileName(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience('https://wrong.example')
            ->clientId(self::CLIENT)
            ->expiresIn(new DateInterval('PT15M'))
            ->build();

        $spy = new SpyLogger();
        try {
            $this->consumerWithLogger($key, $clock, $spy)->parse($jwt->value);
            self::fail('expected audience rejection');
        } catch (InvalidAudienceException) {
            // expected
        }

        self::assertSame(1, $spy->count(), 'claim rejection logged once by the consumer, not also by the validator');
        $record = $spy->last();
        self::assertSame(LogLevel::NOTICE, $record['level']);
        self::assertSame('JWT claim rejected', $record['message']);
        self::assertSame('aud', $record['context']['claim']);
        self::assertSame('access-token', $record['context']['profile']);
    }

    public function testConsumerLogsStructuralParseFailure(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $spy = new SpyLogger();
        try {
            $this->consumerWithLogger($key, $clock, $spy)->parse('not-a-jwt');
            self::fail('expected structural failure');
        } catch (MalformedJwtException) {
            // expected
        }

        $record = $spy->last();
        self::assertSame(LogLevel::WARNING, $record['level']);
        self::assertSame('JWT signature verification failed', $record['message']);
        self::assertSame('access-token', $record['context']['profile']);
        // No usable header before the structural failure → no kid/alg.
        self::assertArrayNotHasKey('kid', $record['context']);
    }

    public function testConsumerLogsSignatureFailure(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $signingKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $wrongKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $jwt = $this->minimalToken($signingKey, $clock);

        $spy = new SpyLogger();
        try {
            $this->consumerWithLogger($wrongKey, $clock, $spy)->parse($jwt->value);
            self::fail('expected signature failure');
        } catch (SignatureVerificationException) {
            // expected
        }

        $record = $spy->last();
        self::assertSame(LogLevel::WARNING, $record['level']);
        self::assertSame('JWT signature verification failed', $record['message']);
        self::assertSame('SignatureVerificationException', $record['context']['reason']);
        self::assertSame('access-token', $record['context']['profile']);
    }

    public function testStructuralFailureWithoutLoggerStillThrowsCleanly(): void
    {
        // No logger attached: the consumer's failure paths must still rethrow
        // the typed exception (pins the null-safe logging calls).
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $this->expectException(MalformedJwtException::class);

        $this->consumer($key, $clock)->parse('not-a-jwt');
    }

    public function testSignatureFailureWithoutLoggerStillThrowsCleanly(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $signingKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $wrongKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $jwt = $this->minimalToken($signingKey, $clock);

        $this->expectException(SignatureVerificationException::class);

        $this->consumer($wrongKey, $clock)->parse($jwt->value);
    }

    public function testConsumerToleratesExpiryWithinLeeway(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->minimalToken($key, $clock); // exp = +15m

        // The resource server's clock sits 30s past the token's `exp` — the
        // ordinary issuer/verifier skew RFC 7519 §4.1.4 anticipates.
        $clock->tick(new DateInterval('PT15M30S'));

        $claims = $this->consumerWithLeeway($key, $clock, new DateInterval('PT1M'))->parse($jwt->value);

        self::assertSame('user-123', $claims->subject());
    }

    public function testConsumerWithoutLeewayRejectsTheSameSkewedToken(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->minimalToken($key, $clock);
        $clock->tick(new DateInterval('PT15M30S'));

        // Same token, same clock, no leeway: the default stays strict, so the
        // acceptance above is the leeway's doing and nothing else.
        $this->expectException(ExpiredException::class);

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testConsumerRejectsLeewayAboveTheCeiling(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        // The bound is ValidatorBuilder's; the factory must not smuggle a
        // value past it, because leeway widens the window in which an expired
        // token is still accepted.
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('exceeds the hard ceiling');

        $this->consumerWithLeeway($key, $clock, new DateInterval('PT' . (ValidatorBuilder::LEEWAY_CEILING_SECONDS + 1) . 'S'));
    }

    private function issuer(HmacKey $key, FrozenClock $clock): AccessTokenProfile
    {
        return AccessTokenProfile::issuer(self::ISSUER, new Hs256(), $key, $clock);
    }

    private function consumerWithLogger(HmacKey $key, FrozenClock $clock, SpyLogger $logger): AccessTokenConsumer
    {
        return AccessTokenProfile::consumer(
            self::ISSUER,
            self::AUDIENCE,
            JwkSet::of($key),
            [new Hs256()],
            $clock,
            $logger,
        );
    }

    private function consumer(HmacKey $key, FrozenClock $clock): AccessTokenConsumer
    {
        return AccessTokenProfile::consumer(
            self::ISSUER,
            self::AUDIENCE,
            JwkSet::of($key),
            [new Hs256()],
            $clock,
        );
    }

    private function consumerWithLeeway(HmacKey $key, FrozenClock $clock, DateInterval $leeway): AccessTokenConsumer
    {
        return AccessTokenProfile::consumer(
            self::ISSUER,
            self::AUDIENCE,
            JwkSet::of($key),
            [new Hs256()],
            $clock,
            leeway: $leeway,
        );
    }

    private function minimalToken(HmacKey $key, FrozenClock $clock): CompactJws
    {
        return $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::AUDIENCE)
            ->clientId(self::CLIENT)
            ->expiresIn(new DateInterval('PT15M'))
            ->build();
    }
}
