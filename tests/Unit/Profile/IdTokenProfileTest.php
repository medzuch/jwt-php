<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Profile;

use DateInterval;
use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Exception\InvalidClaimException;
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
use Medzuch\Jwt\Profile\IdTokenBuilder;
use Medzuch\Jwt\Profile\IdTokenConsumer;
use Medzuch\Jwt\Profile\IdTokenProfile;
use Medzuch\Jwt\Profile\ProfileConsumer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(IdTokenProfile::class)]
#[CoversClass(IdTokenBuilder::class)]
#[CoversClass(IdTokenConsumer::class)]
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
final class IdTokenProfileTest extends TestCase
{
    private const ISSUER = 'https://issuer.example';
    private const CLIENT = 'client-abc';

    public function testRoundTripIdTokenIsAcceptedByConsumer(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::CLIENT)
            ->expiresIn(new DateInterval('PT5M'))
            ->build();

        $claims = $this->consumer($key, $clock)->parse($jwt->value);

        self::assertSame('user-123', $claims->subject());
        self::assertSame([self::CLIENT], $claims->audience());
        // OIDC Core does not mandate a typ; the profile does not stamp one.
        self::assertNull(JwtParser::parse($jwt->value)->header->type());
    }

    public function testAuthorizedPartyMatchingClientIsAccepted(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::CLIENT)
            ->authorizedParty(self::CLIENT)
            ->expiresIn(new DateInterval('PT5M'))
            ->build();

        $claims = $this->consumer($key, $clock)->parse($jwt->value);

        self::assertSame(self::CLIENT, $claims->getString('azp'));
    }

    public function testAuthorizedPartyMismatchIsRejected(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::CLIENT)
            ->authorizedParty('someone-else')
            ->expiresIn(new DateInterval('PT5M'))
            ->build();

        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/azp/');

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testMultipleAudiencesRequireAzp(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience([self::CLIENT, 'https://resource.example'])
            ->expiresIn(new DateInterval('PT5M'))
            ->build();

        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/multiple audiences/');

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testMultipleAudiencesWithAzpAreAccepted(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience([self::CLIENT, 'https://resource.example'])
            ->authorizedParty(self::CLIENT)
            ->expiresIn(new DateInterval('PT5M'))
            ->build();

        $claims = $this->consumer($key, $clock)->parse($jwt->value);

        self::assertSame('user-123', $claims->subject());
    }

    public function testNonceMatchingExpectedIsAccepted(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::CLIENT)
            ->nonce('n-0S6_WzA2Mj')
            ->expiresIn(new DateInterval('PT5M'))
            ->build();

        $claims = $this->consumer($key, $clock, expectedNonce: 'n-0S6_WzA2Mj')->parse($jwt->value);

        self::assertSame('n-0S6_WzA2Mj', $claims->getString('nonce'));
    }

    public function testNonceMismatchIsRejected(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::CLIENT)
            ->nonce('attacker-nonce')
            ->expiresIn(new DateInterval('PT5M'))
            ->build();

        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/nonce/');

        $this->consumer($key, $clock, expectedNonce: 'expected-nonce')->parse($jwt->value);
    }

    public function testNonceExpectedButAbsentIsRejected(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::CLIENT)
            ->expiresIn(new DateInterval('PT5M'))
            ->build();

        $this->expectException(InvalidClaimException::class);

        $this->consumer($key, $clock, expectedNonce: 'expected-nonce')->parse($jwt->value);
    }

    public function testConsumerRejectsMissingSubject(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        // iss/iat auto, aud set, exp set — but no sub.
        $jwt = JwtBuilder::create($clock)
            ->issuer(self::ISSUER)
            ->audience(self::CLIENT)
            ->issuedAtNow()
            ->expiresIn(new DateInterval('PT5M'))
            ->signWith(new Hs256(), $key)
            ->build();

        $this->expectException(MissingClaimException::class);
        $this->expectExceptionMessageMatches('/sub/');

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testOptionalClaimHelpersPassThrough(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::CLIENT)
            ->authTime(new \DateTimeImmutable('2026-05-21T00:00:00+00:00'))
            ->acr('urn:mace:incommon:iap:silver')
            ->amr(['pwd', 'otp'])
            ->notBefore(new \DateTimeImmutable('2026-05-21T00:00:00+00:00'))
            ->jwtId('id-1')
            ->expiresIn(new DateInterval('PT5M'))
            ->withClaim('email', 'user@example.com')
            ->withHeader('cty', 'application/example')
            ->build();

        $parsed = JwtParser::parse($jwt->value);
        $claims = $parsed->unverifiedClaims;

        self::assertSame('urn:mace:incommon:iap:silver', $claims->getString('acr'));
        self::assertSame(['pwd', 'otp'], $claims->getList('amr'));
        self::assertNotNull($claims->getInt('auth_time'));
        self::assertSame('user@example.com', $claims->getString('email'));
        self::assertSame('id-1', $claims->jwtId());
        self::assertSame('application/example', $parsed->header->contentType());
    }

    public function testKidHeaderSetWhenKeyHasKidAndOmittedOtherwise(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');

        $keyed = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $withKid = $this->issuer($keyed, $clock)->issue()
            ->subject('user-123')
            ->audience(self::CLIENT)
            ->expiresIn(new DateInterval('PT5M'))
            ->build();
        self::assertSame('k1', JwtParser::parse($withKid->value)->header->keyId());

        $bare = HmacKey::fromBinary(random_bytes(32), 'HS256'); // no kid
        $withoutKid = $this->issuer($bare, $clock)->issue()
            ->subject('user-123')
            ->audience(self::CLIENT)
            ->expiresIn(new DateInterval('PT5M'))
            ->build();
        self::assertFalse(JwtParser::parse($withoutKid->value)->header->has('kid'));
    }

    public function testExpiresAtAndIssuedAtPassThrough(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $exp = new \DateTimeImmutable('2026-05-21T00:05:00+00:00');
        $iat = new \DateTimeImmutable('2026-05-20T23:59:00+00:00');

        $jwt = $this->issuer($key, $clock)->issue()
            ->subject('user-123')
            ->audience(self::CLIENT)
            ->issuedAt($iat)
            ->expiresAt($exp)
            ->build();

        $claims = $this->consumer($key, $clock)->parse($jwt->value);

        self::assertSame($exp->getTimestamp(), $claims->expiresAt()?->getTimestamp());
        self::assertSame($iat->getTimestamp(), $claims->issuedAt()?->getTimestamp());
    }

    private function issuer(HmacKey $key, FrozenClock $clock): IdTokenProfile
    {
        return IdTokenProfile::issuer(self::ISSUER, new Hs256(), $key, $clock);
    }

    private function consumer(HmacKey $key, FrozenClock $clock, ?string $expectedNonce = null): IdTokenConsumer
    {
        return IdTokenProfile::consumer(
            self::ISSUER,
            self::CLIENT,
            JwkSet::of($key),
            [new Hs256()],
            $expectedNonce,
            $clock,
        );
    }
}
