<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jws;

use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Unit coverage for the RFC 7797 `b64:false` flow across Signer / Verifier /
 * CompactSerializer — embedded, detached, and the negative shapes that must
 * stay refused. The published RFC 7797 §A.1 vector lives in the conformance
 * suite ({@see \Medzuch\Jwt\Tests\Conformance\Rfc7797AppendixA1Test}); the
 * tests here exercise edge cases the appendix does not.
 */
#[CoversClass(Signer::class)]
#[CoversClass(Verifier::class)]
#[CoversClass(CompactSerializer::class)]
#[UsesClass(\Medzuch\Jwt\Jws\Internal\B64Header::class)]
#[UsesClass(\Medzuch\Jwt\Jws\Internal\HeaderShape::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(JwkSet::class)]
#[UsesClass(StaticJwkSetResolver::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\AlgorithmFamily::class)]
#[UsesClass(\Medzuch\Jwt\Jws\CompactJws::class)]
#[UsesClass(\Medzuch\Jwt\Jws\ParsedJws::class)]
#[UsesClass(\Medzuch\Jwt\Key\Internal\JwkAttributes::class)]
#[UsesClass(\Medzuch\Jwt\Key\Key::class)]
#[UsesClass(\Medzuch\Jwt\Key\KeyUse::class)]
#[UsesClass(\Medzuch\Jwt\Key\SymmetricKey::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Json::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Utf8::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\ConstantTime::class)]
final class B64UnencodedTest extends TestCase
{
    public function testEmbeddedUnencodedRoundTrip(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $signed = (new Signer())->sign(
            new Hs256(),
            ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']],
            'hello world',
            $key,
        );

        // Middle segment is the raw payload bytes, not base64url-encoded.
        [, $middle] = explode('.', $signed->value, 2);
        self::assertStringStartsWith('hello world.', $middle);

        $parsed = CompactSerializer::deserialize($signed->value);
        self::assertSame('hello world', $parsed->payload);

        $verified = (new Verifier())->verify($parsed, [new Hs256()], new StaticJwkSetResolver(JwkSet::of($key)));
        self::assertSame('hello world', $verified->payload);
    }

    public function testDetachedUnencodedRoundTrip(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $payload = 'binary-blob-with-bytes-' . random_bytes(8);

        $signed = (new Signer())->sign(
            new Hs256(),
            ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']],
            $payload,
            $key,
            detached: true,
        );

        // Middle segment is empty in the detached form.
        $parts = explode('.', $signed->value);
        self::assertCount(3, $parts);
        self::assertSame('', $parts[1]);

        $parsed = CompactSerializer::deserialize($signed->value);
        self::assertSame('', $parsed->payload);

        $verified = (new Verifier())->verifyDetached(
            $parsed,
            $payload,
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($key)),
        );
        self::assertSame($payload, $verified->payload);
    }

    public function testDetachedEncodedRoundTrip(): void
    {
        // Detached works with the default `b64:true` too — the payload
        // segment is empty on the wire and the verifier re-encodes the
        // external payload before reconstructing the signing input.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $payload = '{"sub":"user-1"}';

        $signed = (new Signer())->sign(new Hs256(), ['alg' => 'HS256'], $payload, $key, detached: true);

        $parts = explode('.', $signed->value);
        self::assertCount(3, $parts);
        self::assertSame('', $parts[1]);

        $parsed = CompactSerializer::deserialize($signed->value);
        $verified = (new Verifier())->verifyDetached(
            $parsed,
            $payload,
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($key)),
        );
        self::assertSame($payload, $verified->payload);
    }

    public function testVerifyRefusesDetachedJws(): void
    {
        // Calling verify() on a detached JWS would compute the wrong
        // signing input. The wrong-shape boundary check makes the caller
        // route through verifyDetached() instead.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $signed = (new Signer())->sign(new Hs256(), ['alg' => 'HS256'], 'payload', $key, detached: true);
        $parsed = CompactSerializer::deserialize($signed->value);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/Detached JWS.*verifyDetached/');

        (new Verifier())->verify($parsed, [new Hs256()], new StaticJwkSetResolver(JwkSet::of($key)));
    }

    public function testVerifyDetachedRefusesNonDetachedJws(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $signed = (new Signer())->sign(new Hs256(), ['alg' => 'HS256'], 'payload', $key);
        $parsed = CompactSerializer::deserialize($signed->value);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/not detached.*verify\(\)/');

        (new Verifier())->verifyDetached($parsed, 'payload', [new Hs256()], new StaticJwkSetResolver(JwkSet::of($key)));
    }

    public function testVerifyDetachedRejectsWrongExternalPayload(): void
    {
        // Substituting a different payload at verify must fail the
        // signature check — the AEAD-equivalent guarantee for JWS.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $signed = (new Signer())->sign(new Hs256(), ['alg' => 'HS256'], 'original-payload', $key, detached: true);
        $parsed = CompactSerializer::deserialize($signed->value);

        $this->expectException(SignatureVerificationException::class);

        (new Verifier())->verifyDetached(
            $parsed,
            'tampered-payload',
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($key)),
        );
    }

    public function testSignerRefusesB64FalseWithoutCrit(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"b64":false.*crit.*"b64"/');

        (new Signer())->sign(new Hs256(), ['alg' => 'HS256', 'b64' => false], 'payload', $key);
    }

    public function testSignerRefusesB64FalseWhenCritOmitsB64(): void
    {
        // crit lists a non-b64 extension — Signer must refuse before
        // minting a token (RFC 7515 §4.1.11 + RFC 7797 §6). The shared
        // helper rejects on the unsupported-extension branch first; either
        // path is a correct refusal.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"crit".*(unsupported|"b64")/');

        (new Signer())->sign(new Hs256(), ['alg' => 'HS256', 'b64' => false, 'crit' => ['other-ext']], 'payload', $key);
    }

    public function testSignerRefusesCritWithUnsupportedExtensionAlongsideB64(): void
    {
        // Reviewer's case: producer included a known + unknown extension. The
        // shared helper must refuse — otherwise the same library refuses to
        // round-trip the token its Signer just emitted.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"crit".*unsupported extension.*x5u/');

        (new Signer())->sign(new Hs256(), ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64', 'x5u']], 'payload', $key);
    }

    public function testSignerRefusesCritListingB64WhenB64Absent(): void
    {
        // RFC 7515 §4.1.11: names in crit must be header members.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"crit" lists "b64".*"b64" header parameter is not present/');

        (new Signer())->sign(new Hs256(), ['alg' => 'HS256', 'crit' => ['b64']], 'payload', $key);
    }

    public function testSignerRefusesNonBooleanB64(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"b64".*boolean/');

        (new Signer())->sign(new Hs256(), ['alg' => 'HS256', 'b64' => 'false'], 'payload', $key);
    }

    public function testCompactSerializerRefusesB64FalseWithoutCrit(): void
    {
        // A token from a less-strict producer that omitted `crit:["b64"]`
        // must not parse — defence in depth, even though our own Signer
        // never emits such a token.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');
        $jws = CompactSerializer::serialize(['alg' => 'HS256', 'b64' => false], 'payload', "\x00");

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"b64":false.*crit/');

        CompactSerializer::deserialize($jws->value);
    }

    public function testCompactSerializerRefusesUnknownCritExtension(): void
    {
        $jws = CompactSerializer::serialize(
            ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64', 'unknown-ext']],
            'payload',
            "\x00",
        );

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"crit".*unsupported.*unknown-ext/');

        CompactSerializer::deserialize($jws->value);
    }

    public function testEmbeddedPayloadWithDotRoundTrips(): void
    {
        // The RFC 7797 §5.2 SHOULD-discouraged case: embedded payload that
        // contains `.`. The split-on-first-and-last rule recovers it.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $payload = 'a.b.c';

        $signed = (new Signer())->sign(
            new Hs256(),
            ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']],
            $payload,
            $key,
        );

        self::assertCount(5, explode('.', $signed->value));

        $parsed = CompactSerializer::deserialize($signed->value);
        self::assertSame($payload, $parsed->payload);

        $verified = (new Verifier())->verify($parsed, [new Hs256()], new StaticJwkSetResolver(JwkSet::of($key)));
        self::assertSame($payload, $verified->payload);
    }
}
