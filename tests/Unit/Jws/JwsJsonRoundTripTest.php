<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jws;

use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Hs384;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Medzuch\Jwt\Jws\JsonSerializer;
use Medzuch\Jwt\Jws\SignatureSpec;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end Signer → JsonSerializer → Verifier round-trips for the JWS
 * JSON Serialization (flattened and general). The multi-signature general
 * round-trip with two algorithm families (HS256 + RS256) is Phase 4 exit
 * criterion #3.
 */
#[CoversClass(Signer::class)]
#[CoversClass(JsonSerializer::class)]
#[CoversClass(SignatureSpec::class)]
#[UsesClass(Verifier::class)]
#[UsesClass(\Medzuch\Jwt\Jws\FlattenedJws::class)]
#[UsesClass(\Medzuch\Jwt\Jws\GeneralJws::class)]
#[UsesClass(\Medzuch\Jwt\Jws\ParsedJsonJws::class)]
#[UsesClass(\Medzuch\Jwt\Jws\ParsedJws::class)]
#[UsesClass(\Medzuch\Jwt\Jws\CompactSerializer::class)]
#[UsesClass(\Medzuch\Jwt\Jws\Internal\B64Header::class)]
#[UsesClass(\Medzuch\Jwt\Jws\Internal\HeaderShape::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(Hs384::class)]
#[UsesClass(Rs256::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Signing\RsaSigningAlgorithm::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\AlgorithmFamily::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(RsaPrivateKey::class)]
#[UsesClass(RsaPublicKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\AsymmetricKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\Internal\Asn1::class)]
#[UsesClass(\Medzuch\Jwt\Key\Internal\JwkAttributes::class)]
#[UsesClass(JwkSet::class)]
#[UsesClass(StaticJwkSetResolver::class)]
#[UsesClass(\Medzuch\Jwt\Key\Key::class)]
#[UsesClass(\Medzuch\Jwt\Key\SymmetricKey::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(Json::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Utf8::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\ConstantTime::class)]
final class JwsJsonRoundTripTest extends TestCase
{
    public function testFlattenedRoundTrip(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $flat = (new Signer())->signFlattened(
            new Hs256(),
            ['alg' => 'HS256', 'kid' => 'k1'],
            'payload-bytes',
            $key,
            unprotectedHeader: ['note' => 'unauthenticated'],
        );

        $parsed = JsonSerializer::deserialize($flat->value);
        self::assertSame('payload-bytes', $parsed->payload);

        // Effective header carries the unprotected member.
        self::assertSame('unauthenticated', $parsed->single()->header['note']);

        $verified = (new Verifier())->verify(
            $parsed->single(),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($key)),
        );
        self::assertSame('payload-bytes', $verified->payload);
    }

    /**
     * Phase 4 exit criterion #3: round-trip with two signatures of
     * different algorithms (HS256 symmetric + RS256 asymmetric).
     */
    public function testGeneralRoundTripWithTwoAlgorithms(): void
    {
        $hmacKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'hmac-1');
        [$rsaPrivate, $rsaPublic] = $this->rsaKeyPair('rsa-1');

        $general = (new Signer())->signGeneral(
            [
                new SignatureSpec(new Hs256(), ['alg' => 'HS256', 'kid' => 'hmac-1'], $hmacKey),
                new SignatureSpec(new Rs256(), ['alg' => 'RS256', 'kid' => 'rsa-1'], $rsaPrivate),
            ],
            'shared-payload',
        );

        $parsed = JsonSerializer::deserialize($general->value);
        self::assertSame('shared-payload', $parsed->payload);
        self::assertCount(2, $parsed->signatures);

        // Verify both signatures, each with its own algorithm and key. The
        // resolver returns the right key based on `kid`.
        $resolver = new StaticJwkSetResolver(JwkSet::of($hmacKey, $rsaPublic));
        $verifier = new Verifier();

        $verifier->verify($parsed->signatures[0], [new Hs256()], $resolver);
        $verifier->verify($parsed->signatures[1], [new Rs256()], $resolver);

        // Each signature's protected header reflects its own alg.
        self::assertSame('HS256', $parsed->signatures[0]->header['alg']);
        self::assertSame('RS256', $parsed->signatures[1]->header['alg']);
    }

    public function testGeneralWithSameAlgDifferentKidRoundTrip(): void
    {
        // Two signatures, same alg family, different keys — the realistic
        // "issued to multiple recipients" case.
        $k1 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $k2 = HmacKey::fromBinary(random_bytes(48), 'HS384', kid: 'k2');

        $general = (new Signer())->signGeneral(
            [
                new SignatureSpec(new Hs256(), ['alg' => 'HS256', 'kid' => 'k1'], $k1),
                new SignatureSpec(new Hs384(), ['alg' => 'HS384', 'kid' => 'k2'], $k2),
            ],
            '{"sub":"user-1"}',
        );

        $parsed = JsonSerializer::deserialize($general->value);
        $resolver = new StaticJwkSetResolver(JwkSet::of($k1, $k2));
        $verifier = new Verifier();

        $v0 = $verifier->verify($parsed->signatures[0], [new Hs256(), new Hs384()], $resolver);
        $v1 = $verifier->verify($parsed->signatures[1], [new Hs256(), new Hs384()], $resolver);

        self::assertSame('{"sub":"user-1"}', $v0->payload);
        self::assertSame('{"sub":"user-1"}', $v1->payload);
    }

    public function testTamperedPayloadFailsAllSignatures(): void
    {
        $k1 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $k2 = HmacKey::fromBinary(random_bytes(48), 'HS384', kid: 'k2');

        $general = (new Signer())->signGeneral(
            [
                new SignatureSpec(new Hs256(), ['alg' => 'HS256', 'kid' => 'k1'], $k1),
                new SignatureSpec(new Hs384(), ['alg' => 'HS384', 'kid' => 'k2'], $k2),
            ],
            'original',
        );

        // Substitute a different `payload` member in the JSON.
        $object = Json::decode($general->value);
        $object['payload'] = Base64Url::encode('tampered');
        $tampered = Json::encode($object);

        $parsed = JsonSerializer::deserialize($tampered);
        $resolver = new StaticJwkSetResolver(JwkSet::of($k1, $k2));
        $verifier = new Verifier();

        // Both signatures must fail — they were over `original`, not `tampered`.
        $this->expectException(SignatureVerificationException::class);
        $verifier->verify($parsed->signatures[0], [new Hs256()], $resolver);
    }

    public function testDetachedGeneralRoundTrip(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $general = (new Signer())->signGeneral(
            [new SignatureSpec(new Hs256(), ['alg' => 'HS256', 'kid' => 'k1'], $key)],
            'external-payload-bytes',
            detached: true,
        );

        // The wire form has no `payload` member.
        self::assertArrayNotHasKey('payload', Json::decode($general->value));

        $parsed = JsonSerializer::deserialize($general->value);
        // Detached: parser carries an empty payload, the caller delivers
        // the external bytes to Verifier::verifyDetached().
        self::assertSame('', $parsed->payload);

        $verified = (new Verifier())->verifyDetached(
            $parsed->single(),
            'external-payload-bytes',
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($key)),
        );
        self::assertSame('external-payload-bytes', $verified->payload);
    }

    public function testB64FalseFlattenedRoundTrip(): void
    {
        // RFC 7797 §4.2: the JSON `payload` member is the raw bytes when
        // b64:false. The signing input still concatenates the raw payload
        // (RFC 7797 §3), so the same Verifier reconstructs it.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $flat = (new Signer())->signFlattened(
            new Hs256(),
            ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64'], 'kid' => 'k1'],
            '$.02',
            $key,
        );

        self::assertSame('$.02', Json::decode($flat->value)['payload']);

        $parsed = JsonSerializer::deserialize($flat->value);
        self::assertSame('$.02', $parsed->payload);

        $verified = (new Verifier())->verify(
            $parsed->single(),
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($key)),
        );
        self::assertSame('$.02', $verified->payload);
    }

    public function testSignerRefusesB64DisagreementAcrossSignatures(): void
    {
        $k1 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $k2 = HmacKey::fromBinary(random_bytes(48), 'HS384', kid: 'k2');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/agree on "b64"/');

        (new Signer())->signGeneral(
            [
                new SignatureSpec(new Hs256(), ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64'], 'kid' => 'k1'], $k1),
                new SignatureSpec(new Hs384(), ['alg' => 'HS384', 'kid' => 'k2'], $k2),
            ],
            'payload',
        );
    }

    public function testSignerRefusesEmptySignaturesList(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/at least one signature/');

        (new Signer())->signGeneral([], 'payload');
    }

    /**
     * @return array{0: RsaPrivateKey, 1: RsaPublicKey}
     */
    private function rsaKeyPair(string $kid): array
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $resource);
        openssl_pkey_export($resource, $privatePem);
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        $publicPem = $details['key'];
        self::assertIsString($publicPem);

        return [
            RsaPrivateKey::fromPem((string) $privatePem, 'RS256', kid: $kid),
            RsaPublicKey::fromPem($publicPem, 'RS256', kid: $kid),
        ];
    }
}
