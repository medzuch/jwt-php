<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Profile;

use LogicException;
use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Exception\ClaimTypeException;
use Medzuch\Jwt\Exception\InvalidAudienceException;
use Medzuch\Jwt\Exception\InvalidClaimException;
use Medzuch\Jwt\Exception\InvalidTypeException;
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
use Medzuch\Jwt\Profile\ProfileConsumer;
use Medzuch\Jwt\Profile\SetBuilder;
use Medzuch\Jwt\Profile\SetConsumer;
use Medzuch\Jwt\Profile\SetProfile;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SetProfile::class)]
#[CoversClass(SetBuilder::class)]
#[CoversClass(SetConsumer::class)]
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
final class SetProfileTest extends TestCase
{
    private const ISSUER = 'https://issuer.example';
    private const AUDIENCE = 'https://receiver.example';
    private const EVENT = 'https://schemas.openid.net/secevent/risc/event-type/account-disabled';

    public function testRoundTripSetIsAcceptedByConsumer(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->audience(self::AUDIENCE)
            ->subject('user-123')
            ->event(self::EVENT, ['reason' => 'hijacking'])
            ->build();

        $parsed = JwtParser::parse($jwt->value);
        self::assertSame('secevent+jwt', $parsed->header->type());
        self::assertSame('k1', $parsed->header->keyId());
        self::assertSame(32, strlen((string) $parsed->unverifiedClaims->jwtId()));

        $claims = $this->consumer($key, $clock)->parse($jwt->value);

        self::assertNotNull($claims->jwtId());
        self::assertNotNull($claims->issuedAt());
        $events = $claims->get('events');
        self::assertIsArray($events);
        self::assertArrayHasKey(self::EVENT, $events);
    }

    public function testMultipleEventsAccumulate(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $other = 'https://schemas.openid.net/secevent/risc/event-type/account-enabled';

        $jwt = $this->issuer($key, $clock)->issue()
            ->event(self::EVENT, ['reason' => 'hijacking'])
            ->event($other)
            ->transactionId('txn-42')
            ->timeOfEvent(new \DateTimeImmutable('2026-05-20T23:00:00+00:00'))
            ->build();

        $claims = $this->consumer($key, $clock)->parse($jwt->value);
        $events = $claims->get('events');

        self::assertIsArray($events);
        self::assertArrayHasKey(self::EVENT, $events);
        self::assertArrayHasKey($other, $events);
        self::assertSame('txn-42', $claims->getString('txn'));
        self::assertNotNull($claims->getInt('toe'));
    }

    public function testEmptyEventPayloadSerialisesAsObject(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->event(self::EVENT)
            ->build();

        $payloadJson = Base64Url::decode(explode('.', $jwt->value)[1]);

        // The empty payload must be a JSON object `{}`, never an array `[]`.
        self::assertStringContainsString('{}', $payloadJson);
        self::assertStringNotContainsString('[]', $payloadJson);
    }

    public function testBuildWithoutEventsFails(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/at least one event/');

        $this->issuer($key, $clock)->issue()->build();
    }

    public function testEmptyEventTypeFails(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/non-empty URI/');

        $this->issuer($key, $clock)->issue()->event('');
    }

    public function testConsumerRejectsMissingType(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        // A SET-shaped token that omits the secevent+jwt type.
        $jwt = JwtBuilder::create($clock)
            ->issuer(self::ISSUER)
            ->issuedAtNow()
            ->jwtId('j1')
            ->withClaim('events', [self::EVENT => new \stdClass()])
            ->signWith(new Hs256(), $key)
            ->build();

        $this->expectException(InvalidTypeException::class);

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testConsumerRejectsNonObjectEvents(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($clock)
            ->issuer(self::ISSUER)
            ->issuedAtNow()
            ->jwtId('j1')
            ->withClaim('events', 'not-an-object')
            ->type(MediaType::securityEventToken())
            ->signWith(new Hs256(), $key)
            ->build();

        $this->expectException(ClaimTypeException::class);

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testConsumerRejectsArrayShapedEvents(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        // A populated JSON array is the wrong shape — `events` is an object.
        $jwt = JwtBuilder::create($clock)
            ->issuer(self::ISSUER)
            ->issuedAtNow()
            ->jwtId('j1')
            ->withClaim('events', [self::EVENT, 'https://other.example/event'])
            ->type(MediaType::securityEventToken())
            ->signWith(new Hs256(), $key)
            ->build();

        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/non-empty JSON object/');

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testConsumerRejectsEmptyEventsObject(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = JwtBuilder::create($clock)
            ->issuer(self::ISSUER)
            ->issuedAtNow()
            ->jwtId('j1')
            ->withClaim('events', new \stdClass())
            ->type(MediaType::securityEventToken())
            ->signWith(new Hs256(), $key)
            ->build();

        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/non-empty JSON object/');

        $this->consumer($key, $clock)->parse($jwt->value);
    }

    public function testExpectedAudienceIsEnforced(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->audience('https://wrong.example')
            ->event(self::EVENT)
            ->build();

        $this->expectException(InvalidAudienceException::class);

        $this->consumer($key, $clock, self::AUDIENCE)->parse($jwt->value);
    }

    public function testWithClaimAndWithHeaderPassThrough(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $jwt = $this->issuer($key, $clock)->issue()
            ->event(self::EVENT)
            ->notBefore(new \DateTimeImmutable('2026-05-21T00:00:00+00:00'))
            ->withClaim('sid', 'session-9')
            ->withHeader('cty', 'application/example')
            ->build();

        $parsed = JwtParser::parse($jwt->value);

        self::assertSame('session-9', $parsed->unverifiedClaims->getString('sid'));
        self::assertSame('application/example', $parsed->header->contentType());
    }

    public function testIssueOmitsKidHeaderWhenKeyHasNoKid(): void
    {
        $clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256'); // no kid

        $jwt = $this->issuer($key, $clock)->issue()
            ->event(self::EVENT)
            ->build();

        self::assertFalse(JwtParser::parse($jwt->value)->header->has('kid'));
    }

    private function issuer(HmacKey $key, FrozenClock $clock): SetProfile
    {
        return SetProfile::issuer(self::ISSUER, new Hs256(), $key, $clock);
    }

    private function consumer(HmacKey $key, FrozenClock $clock, ?string $expectedAudience = null): SetConsumer
    {
        return SetProfile::consumer(
            self::ISSUER,
            JwkSet::of($key),
            [new Hs256()],
            $expectedAudience,
            $clock,
        );
    }
}
