<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Profile;

use DateInterval;
use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Exception\InvalidAudienceException;
use Medzuch\Jwt\Exception\InvalidTypeException;
use Medzuch\Jwt\Exception\MissingClaimException;
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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AccessTokenProfile::class)]
#[CoversClass(AccessTokenBuilder::class)]
#[CoversClass(AccessTokenConsumer::class)]
#[CoversClass(ProfileConsumer::class)]
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

    private function issuer(HmacKey $key, FrozenClock $clock): AccessTokenProfile
    {
        return AccessTokenProfile::issuer(self::ISSUER, new Hs256(), $key, $clock);
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
