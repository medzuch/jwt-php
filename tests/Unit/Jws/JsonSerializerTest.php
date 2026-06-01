<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jws;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jws\JsonSerializer;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Structural tests for the JWS JSON Serialization — no keys or crypto run
 * here. The end-to-end sign→parse→verify round-trip lives in
 * {@see JwsJsonRoundTripTest}.
 */
#[CoversClass(JsonSerializer::class)]
#[UsesClass(\Medzuch\Jwt\Jws\FlattenedJws::class)]
#[UsesClass(\Medzuch\Jwt\Jws\GeneralJws::class)]
#[UsesClass(\Medzuch\Jwt\Jws\ParsedJsonJws::class)]
#[UsesClass(\Medzuch\Jwt\Jws\ParsedJws::class)]
#[UsesClass(\Medzuch\Jwt\Jws\Internal\B64Header::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(Json::class)]
#[UsesClass(\Medzuch\Jwt\Primitives\Utf8::class)]
final class JsonSerializerTest extends TestCase
{
    public function testFlattenedRoundTripPreservesPayloadAndHeader(): void
    {
        $flat = JsonSerializer::serializeFlattened(
            ['alg' => 'HS256', 'kid' => 'k1'],
            ['custom' => 'x'],
            'hello',
            "\x00\x01\x02",
        );

        $parsed = JsonSerializer::deserialize($flat->value);

        self::assertSame('hello', $parsed->payload);
        $sig = $parsed->single();
        self::assertSame('HS256', $sig->header['alg']);
        self::assertSame('k1', $sig->header['kid']);
        // Effective header is protected + unprotected, merged.
        self::assertSame('x', $sig->header['custom']);
        self::assertSame("\x00\x01\x02", $sig->signature);
    }

    public function testGeneralMultiSignatureRoundTrip(): void
    {
        $general = JsonSerializer::serializeGeneral(
            [
                ['protectedHeader' => ['alg' => 'HS256', 'kid' => 'k1'], 'unprotectedHeader' => [], 'signature' => "\x01"],
                ['protectedHeader' => ['alg' => 'HS384', 'kid' => 'k2'], 'unprotectedHeader' => [], 'signature' => "\x02"],
            ],
            'shared-payload',
        );

        // The JSON has exactly the right shape: top-level `payload` and a
        // `signatures` array.
        $object = Json::decode($general->value);
        self::assertArrayHasKey('signatures', $object);
        $signatures = $object['signatures'];
        self::assertIsArray($signatures);
        self::assertCount(2, $signatures);

        $parsed = JsonSerializer::deserialize($general->value);
        self::assertSame('shared-payload', $parsed->payload);
        self::assertCount(2, $parsed->signatures);
        self::assertSame('HS256', $parsed->signatures[0]->header['alg']);
        self::assertSame('HS384', $parsed->signatures[1]->header['alg']);
        self::assertSame('k1', $parsed->signatures[0]->header['kid']);
        self::assertSame('k2', $parsed->signatures[1]->header['kid']);
    }

    public function testFlattenedRejectsDisjointHeaderViolation(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/disjoint.*kid/');

        JsonSerializer::serializeFlattened(
            ['alg' => 'HS256', 'kid' => 'k1'],
            ['kid' => 'k2'],
            'payload',
            "\x00",
        );
    }

    public function testGeneralRejectsB64Disagreement(): void
    {
        // RFC 7797 §5.2: when multi-sig, b64 must agree across all.
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/agree on "b64"/');

        JsonSerializer::serializeGeneral(
            [
                ['protectedHeader' => ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']], 'unprotectedHeader' => [], 'signature' => "\x01"],
                ['protectedHeader' => ['alg' => 'HS256'], 'unprotectedHeader' => [], 'signature' => "\x02"],
            ],
            'payload',
        );
    }

    public function testDetachedEmitsNoPayloadMember(): void
    {
        $flat = JsonSerializer::serializeFlattened(
            ['alg' => 'HS256'],
            [],
            'payload-bytes',
            "\x00",
            detached: true,
        );

        $object = Json::decode($flat->value);
        self::assertArrayNotHasKey('payload', $object);

        $parsed = JsonSerializer::deserialize($flat->value);
        // Detached: parser returns an empty payload; the caller supplies
        // the external bytes to Verifier::verifyDetached().
        self::assertSame('', $parsed->payload);
        self::assertSame('', $parsed->single()->encodedPayload);
    }

    public function testDeserializeRejectsMixingFlattenedAndGeneralFields(): void
    {
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'protected' => Base64Url::encode('{"alg":"HS256"}'),
            'signature' => Base64Url::encode("\x00"),
            'signatures' => [
                ['protected' => Base64Url::encode('{"alg":"HS256"}'), 'signature' => Base64Url::encode("\x00")],
            ],
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/mixes the general.*flattened/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsEmptySignaturesArray(): void
    {
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'signatures' => [],
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"signatures" must be a non-empty/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsB64Disagreement(): void
    {
        // Build a malformed JSON by hand (the producer-side check would
        // catch this — defence in depth on the parse side).
        $protectedFalse = Base64Url::encode(Json::encode(['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']]));
        $protectedTrue = Base64Url::encode(Json::encode(['alg' => 'HS256']));
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'signatures' => [
                ['protected' => $protectedFalse, 'signature' => Base64Url::encode("\x00")],
                ['protected' => $protectedTrue, 'signature' => Base64Url::encode("\x00")],
            ],
        ]);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/agree on "b64"/');

        JsonSerializer::deserialize($json);
    }

    public function testB64FalsePayloadMemberIsRawBytes(): void
    {
        // RFC 7797 §4.2: in JSON form with b64:false the `payload` member
        // is the raw unencoded payload string.
        $flat = JsonSerializer::serializeFlattened(
            ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']],
            [],
            '$.02',                                // payload with a "."
            "\x00",
        );

        $object = Json::decode($flat->value);
        self::assertSame('$.02', $object['payload']);

        $parsed = JsonSerializer::deserialize($flat->value);
        self::assertSame('$.02', $parsed->payload);
    }

    public function testDeserializeRejectsSignatureMemberMissing(): void
    {
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'protected' => Base64Url::encode('{"alg":"HS256"}'),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"signature".*required/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonObjectSignaturesEntry(): void
    {
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'signatures' => ['not-an-object'],
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"signatures" entries must each be a JSON object/');

        JsonSerializer::deserialize($json);
    }
}
