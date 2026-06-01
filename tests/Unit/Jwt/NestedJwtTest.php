<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwt;

use Medzuch\Jwt\Algorithm\Encryption\A128CbcHs256;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A128Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\Dir;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Exception\AlgorithmNotAllowedException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Medzuch\Jwt\Jwe\Encrypter;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Jwt\NestedJwt;
use Medzuch\Jwt\Jwt\NestedJwtBuilder;
use Medzuch\Jwt\Jwt\NestedJwtParser;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(NestedJwt::class)]
#[CoversClass(NestedJwtBuilder::class)]
#[CoversClass(NestedJwtParser::class)]
#[UsesClass(JwtBuilder::class)]
#[UsesClass(\Medzuch\Jwt\Jwt\JwtParser::class)]
#[UsesClass(\Medzuch\Jwt\Jwt\Header::class)]
#[UsesClass(\Medzuch\Jwt\Jwt\ClaimsSet::class)]
#[UsesClass(\Medzuch\Jwt\Jwt\ParsedJwt::class)]
#[UsesClass(\Medzuch\Jwt\Jwt\MediaType::class)]
#[UsesClass(Encrypter::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\Decrypter::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\CompactSerializer::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\JsonSerializer::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\Internal\JweHeader::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\CompactJwe::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\FlattenedJwe::class)]
#[UsesClass(\Medzuch\Jwt\Jwe\ParsedJwe::class)]
#[UsesClass(\Medzuch\Jwt\Jws\Signer::class)]
#[UsesClass(\Medzuch\Jwt\Jws\Verifier::class)]
#[UsesClass(\Medzuch\Jwt\Jws\CompactSerializer::class)]
#[UsesClass(\Medzuch\Jwt\Jws\CompactJws::class)]
#[UsesClass(\Medzuch\Jwt\Jws\ParsedJws::class)]
#[UsesClass(Dir::class)]
#[UsesClass(A128Kw::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\AesKw::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagement\Internal\AesKeyWrap::class)]
#[UsesClass(A256Gcm::class)]
#[UsesClass(A128CbcHs256::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Encryption\AesGcm::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Encryption\AesCbcHmac::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\CekEncryptionResult::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\AlgorithmFamily::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\KeyManagementMode::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Signing\Hs384::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(OctKey::class)]
#[UsesClass(JwkSet::class)]
#[UsesClass(StaticJwkSetResolver::class)]
#[UsesClass(\Medzuch\Jwt\Key\Key::class)]
#[UsesClass(\Medzuch\Jwt\Key\SymmetricKey::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Base64Url::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Json::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Random::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Utf8::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\ConstantTime::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\SystemClock::class)]
final class NestedJwtTest extends TestCase
{
    public function testRoundTripWithExplicitInnerAndOuterTyp(): void
    {
        // Exit criterion: RFC 8725 §3.11 — explicit typing on inner and outer.
        [$parser, $signKey, $encKey] = $this->scaffold();

        $inner = JwtBuilder::create()
            ->type('JWT')                       // inner typ
            ->issuer('https://issuer.example')
            ->subject('user-1')
            ->withClaim('scope', 'read write')
            ->signWith(new Hs256(), $signKey)
            ->build();

        $outer = NestedJwtBuilder::wrap(
            $inner,
            new Dir(),
            new A256Gcm(),
            $encKey,
            ['typ' => 'JWT', 'kid' => 'enc-1'],  // outer typ; cty is auto-injected
        );

        $result = $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );

        self::assertSame('JWT', $result->outerHeader['cty']);
        self::assertSame('JWT', $result->outerHeader['typ']);
        self::assertSame('JWT', $result->inner->header->type());
        self::assertSame('https://issuer.example', $result->inner->unverifiedClaims->issuer());
        self::assertSame('user-1', $result->inner->unverifiedClaims->subject());
        self::assertSame('read write', $result->inner->unverifiedClaims->getString('scope'));
    }

    public function testWrapAddsCtyJwtWhenAbsent(): void
    {
        [, $signKey, $encKey] = $this->scaffold();

        $inner = JwtBuilder::create()->issuer('a')->signWith(new Hs256(), $signKey)->build();
        $outer = NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['kid' => 'enc-1']);

        // The outer protected header now carries cty=JWT. Cheapest verification:
        // round-trip and read it off the parsed outer header.
        $parser = new NestedJwtParser();
        $result = $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );

        self::assertSame('JWT', $result->outerHeader['cty']);
    }

    public function testWrapRefusesNonJwtCty(): void
    {
        [, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->issuer('a')->signWith(new Hs256(), $signKey)->build();

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('cty');

        NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['cty' => 'application/octet-stream']);
    }

    public function testWrapAcceptsExplicitCtyJwt(): void
    {
        // Caller setting cty=JWT explicitly is fine — exactly matches what the
        // helper would have supplied.
        [, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->issuer('a')->signWith(new Hs256(), $signKey)->build();

        $outer = NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['cty' => 'JWT']);

        self::assertNotEmpty($outer->value);
    }

    public function testParseRejectsOuterWithoutCty(): void
    {
        // Build a "would-be nested" JWE by hand via the plain Encrypter (no cty).
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->issuer('a')->signWith(new Hs256(), $signKey)->build();
        $outer = (new Encrypter())->encrypt(new Dir(), new A256Gcm(), ['kid' => 'enc-1'], $inner->value, $encKey);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('cty');

        $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );
    }

    public function testParseRejectsOuterWithWrongCty(): void
    {
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->issuer('a')->signWith(new Hs256(), $signKey)->build();
        $outer = (new Encrypter())->encrypt(new Dir(), new A256Gcm(), ['cty' => 'application/xml', 'kid' => 'enc-1'], $inner->value, $encKey);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"application/xml"');

        $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );
    }

    public function testReplicatedIssClaimConsistencyAccepted(): void
    {
        // §5.3: a producer mirroring `iss` into the outer header is fine
        // as long as it matches the inner claim.
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()
            ->issuer('https://issuer.example')
            ->subject('user-1')
            ->signWith(new Hs256(), $signKey)
            ->build();
        $outer = NestedJwtBuilder::wrap(
            $inner,
            new Dir(),
            new A256Gcm(),
            $encKey,
            ['kid' => 'enc-1', 'iss' => 'https://issuer.example'],
        );

        $result = $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );

        self::assertSame('https://issuer.example', $result->outerHeader['iss']);
        self::assertSame('https://issuer.example', $result->inner->unverifiedClaims->issuer());
    }

    public function testReplicatedClaimMismatchRejected(): void
    {
        // §5.3: outer header replicates `iss` with a different value — MUST reject.
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()
            ->issuer('https://issuer.example')
            ->signWith(new Hs256(), $signKey)
            ->build();
        $outer = NestedJwtBuilder::wrap(
            $inner,
            new Dir(),
            new A256Gcm(),
            $encKey,
            ['kid' => 'enc-1', 'iss' => 'https://attacker.example'],
        );

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"iss"');

        $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );
    }

    public function testReplicatedAudListConsistencyAccepted(): void
    {
        // `aud` may be a list; deep equality applies.
        [$parser, $signKey, $encKey] = $this->scaffold();
        $aud = ['svc-a', 'svc-b'];
        $inner = JwtBuilder::create()->audience($aud)->signWith(new Hs256(), $signKey)->build();
        $outer = NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['kid' => 'enc-1', 'aud' => $aud]);

        $result = $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );

        self::assertSame($aud, $result->outerHeader['aud']);
    }

    public function testReplicatedAudListOrderMismatchRejected(): void
    {
        // The library does not canonicalise list order.
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->audience(['svc-a', 'svc-b'])->signWith(new Hs256(), $signKey)->build();
        $outer = NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['kid' => 'enc-1', 'aud' => ['svc-b', 'svc-a']]);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"aud"');

        $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );
    }

    public function testNonOverlappingClaimsAndHeadersAreNotConstrained(): void
    {
        // Outer has `kid`, inner has `iss` — different keys, no §5.3 check fires.
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->issuer('a')->signWith(new Hs256(), $signKey)->build();
        $outer = NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['kid' => 'enc-1']);

        $result = $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );

        self::assertSame('enc-1', $result->outerHeader['kid']);
        self::assertSame('a', $result->inner->unverifiedClaims->issuer());
    }

    public function testCtyAndTypAreExcludedFromReplicationCheck(): void
    {
        // A producer who put a `cty` *claim* in the inner Claims Set (poor
        // taste, but possible) must not trip the §5.3 check — `cty`/`typ`
        // are JOSE header parameters, not the replicated-claim scenario.
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()
            ->issuer('a')
            ->withClaim('cty', 'something-else')  // weird, but allowed
            ->signWith(new Hs256(), $signKey)
            ->build();
        $outer = NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['kid' => 'enc-1']);

        $result = $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );

        self::assertSame('JWT', $result->outerHeader['cty']);
        self::assertSame('something-else', $result->inner->unverifiedClaims->get('cty'));
    }

    public function testRoundTripWithJsonOuterSerialization(): void
    {
        // The parser sniffs compact vs. JSON. Build the outer as flattened JSON
        // (using Encrypter directly) and round-trip through NestedJwtParser.
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->subject('user-1')->signWith(new Hs256(), $signKey)->build();

        $outer = (new Encrypter())->encryptFlattened(
            new Dir(),
            new A256Gcm(),
            ['cty' => 'JWT', 'typ' => 'JWT', 'kid' => 'enc-1'],
            $inner->value,
            $encKey,
        );

        $result = $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );

        self::assertSame('user-1', $result->inner->unverifiedClaims->subject());
    }

    public function testWrongOuterAlgIsRejected(): void
    {
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->subject('a')->signWith(new Hs256(), $signKey)->build();
        $outer = NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['kid' => 'enc-1']);

        $this->expectException(AlgorithmNotAllowedException::class);

        $parser->parse(
            $outer->value,
            [new A128Kw()],            // does not include Dir
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );
    }

    public function testWrongInnerAlgIsRejected(): void
    {
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->subject('a')->signWith(new Hs256(), $signKey)->build();
        $outer = NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['kid' => 'enc-1']);

        $hs384Allowed = new \Medzuch\Jwt\Algorithm\Signing\Hs384();

        $this->expectException(AlgorithmNotAllowedException::class);

        $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [$hs384Allowed],            // inner signed with HS256, not HS384
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );
    }

    public function testTamperedInnerSignatureIsRejected(): void
    {
        [$parser, $signKey, $encKey] = $this->scaffold();

        // Sign with one HS256 key, hand the verifier a different one.
        $wrongKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'sig-2');

        $inner = JwtBuilder::create()->subject('a')->signWith(new Hs256(), $signKey)->build();
        $outer = NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['kid' => 'enc-1']);

        $this->expectException(SignatureVerificationException::class);

        $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($wrongKey)),
        );
    }

    /**
     * Regression: §5.3 must not flag a custom inner claim that happens to
     * share its name with a JOSE header parameter (here `kid`). The outer
     * `kid` is encryption-key routing metadata — protocol structure, not a
     * replicated claim — and the inner claim sits in a different namespace.
     */
    public function testJoseHeaderParameterNameCollidingWithInnerClaimIsNotChecked(): void
    {
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()
            ->subject('user-1')
            ->withClaim('kid', 'inner-app-specific-value')
            ->signWith(new Hs256(), $signKey)
            ->build();
        $outer = NestedJwtBuilder::wrap(
            $inner,
            new Dir(),
            new A256Gcm(),
            $encKey,
            ['kid' => 'enc-1'],
        );

        $result = $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );

        self::assertSame('enc-1', $result->outerHeader['kid']);
        self::assertSame('inner-app-specific-value', $result->inner->unverifiedClaims->get('kid'));
    }

    /**
     * RFC 7515 §4.1.9: `application/jwt` is the equivalent of bare `JWT`
     * (media type names are case-insensitive and the `application/` prefix
     * is optional). The parser must accept either spelling.
     */
    public function testParseAcceptsApplicationJwtCty(): void
    {
        [$parser, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->subject('a')->signWith(new Hs256(), $signKey)->build();
        $outer = (new Encrypter())->encrypt(new Dir(), new A256Gcm(), ['cty' => 'application/jwt', 'kid' => 'enc-1'], $inner->value, $encKey);

        $result = $parser->parse(
            $outer->value,
            [new Dir()],
            [new A256Gcm()],
            new StaticJwkSetResolver(JwkSet::of($encKey)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );

        self::assertSame('application/jwt', $result->outerHeader['cty']);
    }

    public function testWrapAcceptsApplicationJwtCty(): void
    {
        [, $signKey, $encKey] = $this->scaffold();
        $inner = JwtBuilder::create()->subject('a')->signWith(new Hs256(), $signKey)->build();

        // Wrap must not refuse the wire-equivalent spelling.
        $outer = NestedJwtBuilder::wrap($inner, new Dir(), new A256Gcm(), $encKey, ['cty' => 'application/jwt', 'kid' => 'enc-1']);

        self::assertNotEmpty($outer->value);
    }

    public function testKeyWrapWithCbcHmacRoundTrip(): void
    {
        // Coverage across a non-Dir key-management + CBC-HMAC content-encryption.
        [, $signKey,] = $this->scaffold();
        $kek = OctKey::fromBinary(random_bytes(16), 'A128KW', kid: 'enc-1');

        $inner = JwtBuilder::create()
            ->issuer('https://issuer.example')
            ->subject('user-1')
            ->signWith(new Hs256(), $signKey)
            ->build();

        $outer = NestedJwtBuilder::wrap(
            $inner,
            new A128Kw(),
            new A128CbcHs256(),
            $kek,
            ['iss' => 'https://issuer.example'],
        );

        $parser = new NestedJwtParser();
        $result = $parser->parse(
            $outer->value,
            [new A128Kw()],
            [new A128CbcHs256()],
            new StaticJwkSetResolver(JwkSet::of($kek)),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($signKey)),
        );

        self::assertSame('user-1', $result->inner->unverifiedClaims->subject());
    }

    /**
     * @return array{0: NestedJwtParser, 1: HmacKey, 2: OctKey}
     */
    private function scaffold(): array
    {
        $signKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'sig-1');
        $encKey = OctKey::fromBinary(random_bytes(32), 'A256GCM', kid: 'enc-1');

        return [new NestedJwtParser(), $signKey, $encKey];
    }
}
