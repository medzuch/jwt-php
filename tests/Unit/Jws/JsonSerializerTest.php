<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jws;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jws\JsonSerializer;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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
#[UsesClass(\Medzuch\Jwt\Jws\Internal\HeaderShape::class)]
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

    public function testDeserializeRejectsAlgOnlyInUnprotectedHeader(): void
    {
        // RFC 7515 §4.1.1 / RFC 8725 §3.1: `alg` MUST be carried in the
        // integrity-protected header. A JWS that puts `alg` only in the
        // unauthenticated `header` member would let an attacker steer
        // algorithm selection — refuse it at parse.
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'protected' => Base64Url::encode(Json::encode(['kid' => 'k1'])),
            'header' => ['alg' => 'HS256'],
            'signature' => Base64Url::encode("\x00"),
        ]);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/missing required "alg"/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsAlgMissingFromProtectedHeader(): void
    {
        // No `protected` segment at all, only an unprotected `header` carrying
        // `alg`. Same defence as above, slightly different shape.
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'header' => ['alg' => 'HS256'],
            'signature' => Base64Url::encode("\x00"),
        ]);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/missing required "alg"/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonStringKidInProtectedHeader(): void
    {
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'protected' => Base64Url::encode(Json::encode(['alg' => 'HS256', 'kid' => 42])),
            'signature' => Base64Url::encode("\x00"),
        ]);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"kid" must be a string/');

        JsonSerializer::deserialize($json);
    }

    public function testSerializeGeneralRejectsEmptySignaturesList(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/at least one signature/');

        JsonSerializer::serializeGeneral([], 'payload');
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

    // --- b64/disjoint validation runs on every code path (serialize + parse) ---

    public function testSerializeFlattenedValidatesB64Header(): void
    {
        // A non-boolean `b64` must be refused by serializeFlattened, not just
        // by the parser — the B64Header::assertValid() call guards the
        // producer side too.
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"b64" must be a boolean/');

        JsonSerializer::serializeFlattened(
            ['alg' => 'HS256', 'b64' => 'not-a-bool'],
            [],
            'payload',
            "\x00",
        );
    }

    public function testSerializeGeneralValidatesB64HeaderPerSignature(): void
    {
        // The second signature carries an invalid `b64`; the per-row
        // assertValid() in serializeGeneral must catch it.
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"b64" must be a boolean/');

        JsonSerializer::serializeGeneral(
            [
                ['protectedHeader' => ['alg' => 'HS256'], 'unprotectedHeader' => [], 'signature' => "\x01"],
                ['protectedHeader' => ['alg' => 'HS256', 'b64' => 'not-a-bool'], 'unprotectedHeader' => [], 'signature' => "\x02"],
            ],
            'payload',
        );
    }

    public function testSerializeGeneralRejectsDisjointHeaderViolation(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/disjoint.*kid/');

        JsonSerializer::serializeGeneral(
            [
                ['protectedHeader' => ['alg' => 'HS256', 'kid' => 'k1'], 'unprotectedHeader' => ['kid' => 'k2'], 'signature' => "\x01"],
            ],
            'payload',
        );
    }

    public function testDeserializeValidatesB64Header(): void
    {
        // `alg` is present and well-formed, so HeaderShape passes; the
        // non-boolean `b64` must then be caught by B64Header::assertValid()
        // on the parse path.
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'protected' => Base64Url::encode(Json::encode(['alg' => 'HS256', 'b64' => 'not-a-bool'])),
            'signature' => Base64Url::encode("\x00"),
        ]);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"b64" must be a boolean/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsDisjointBetweenProtectedAndUnprotected(): void
    {
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'protected' => Base64Url::encode(Json::encode(['alg' => 'HS256', 'kid' => 'k1'])),
            'header' => ['kid' => 'k2'],
            'signature' => Base64Url::encode("\x00"),
        ]);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/disjoint.*kid/');

        JsonSerializer::deserialize($json);
    }

    // --- the flattened/general mix check trips on *any* single flattened field ---

    /**
     * Each flattened top-level field, present on its own alongside a
     * `signatures` array, must independently trigger the mix refusal. This
     * pins down every `||` branch in extractSignatures() — a single combined
     * fixture leaves the individual operands untested.
     *
     * @param 'protected'|'header'|'signature' $field
     */
    #[DataProvider('flattenedFieldProvider')]
    public function testDeserializeRejectsAnySingleFlattenedFieldMixedWithGeneral(string $field): void
    {
        $object = [
            'payload' => Base64Url::encode('x'),
            'signatures' => [
                ['protected' => Base64Url::encode('{"alg":"HS256"}'), 'signature' => Base64Url::encode("\x00")],
            ],
        ];
        $object[$field] = match ($field) {
            'protected' => Base64Url::encode('{"alg":"HS256"}'),
            'header' => ['kid' => 'k1'],
            'signature' => Base64Url::encode("\x00"),
        };

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/mixes the general.*flattened/');

        JsonSerializer::deserialize(Json::encode($object));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function flattenedFieldProvider(): iterable
    {
        yield 'protected only' => ['protected'];
        yield 'header only' => ['header'];
        yield 'signature only' => ['signature'];
    }

    public function testDeserializeRejectsNonListSignaturesObject(): void
    {
        // A JSON *object* (associative array) for "signatures" is not a list
        // and must be refused — distinct from the empty-array case.
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'signatures' => ['0' => ['protected' => Base64Url::encode('{"alg":"HS256"}'), 'signature' => Base64Url::encode("\x00")], 'extra' => 1],
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"signatures" must be a non-empty array/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsScalarSignaturesMember(): void
    {
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'signatures' => 'not-an-array',
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"signatures" must be a non-empty array/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsListShapedUnprotectedHeader(): void
    {
        // The `header` member must decode to a JSON object, not an array.
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'protected' => Base64Url::encode('{"alg":"HS256"}'),
            'header' => ['list', 'not', 'object'],
            'signature' => Base64Url::encode("\x00"),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"header".*must be a JSON object/');

        JsonSerializer::deserialize($json);
    }

    public function testFlattenedRoundTripPreservesEmptyUnprotectedObject(): void
    {
        // An explicit empty `header: {}` object is a valid (if pointless)
        // unprotected header and must round-trip without being mistaken for
        // a list.
        $json = Json::encode([
            'payload' => Base64Url::encode('hello'),
            'protected' => Base64Url::encode('{"alg":"HS256"}'),
            'header' => (object) [],
            'signature' => Base64Url::encode("\x00"),
        ]);

        $parsed = JsonSerializer::deserialize($json);

        self::assertSame('hello', $parsed->payload);
        self::assertSame('HS256', $parsed->single()->header['alg']);
    }

    public function testFlattenedRoundTripPreservesMultiKeyUnprotectedHeader(): void
    {
        // More than one unprotected member must survive the round-trip — a
        // mutant that keeps only the first array item would be caught here.
        $flat = JsonSerializer::serializeFlattened(
            ['alg' => 'HS256'],
            ['a' => '1', 'b' => '2', 'c' => '3'],
            'hello',
            "\x00",
        );

        $sig = JsonSerializer::deserialize($flat->value)->single();

        self::assertSame('1', $sig->header['a']);
        self::assertSame('2', $sig->header['b']);
        self::assertSame('3', $sig->header['c']);
    }

    public function testB64DisagreementMessageNamesBothValues(): void
    {
        // Pins the describe() match arms: a false/true disagreement must be
        // reported with each side spelled out.
        $protectedFalse = Base64Url::encode(Json::encode(['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']]));
        $protectedTrue = Base64Url::encode(Json::encode(['alg' => 'HS256', 'b64' => true]));
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'signatures' => [
                ['protected' => $protectedFalse, 'signature' => Base64Url::encode("\x00")],
                ['protected' => $protectedTrue, 'signature' => Base64Url::encode("\x00")],
            ],
        ]);

        try {
            JsonSerializer::deserialize($json);
            self::fail('Expected InvalidHeaderException');
        } catch (InvalidHeaderException $e) {
            self::assertStringContainsString('has false', $e->getMessage());
            self::assertStringContainsString('has true', $e->getMessage());
        }
    }

    public function testB64DisagreementMessageDescribesAbsentValue(): void
    {
        // The `absent` (null) describe() arm: first signature omits b64,
        // second sets it true.
        $protectedAbsent = Base64Url::encode(Json::encode(['alg' => 'HS256']));
        $protectedTrue = Base64Url::encode(Json::encode(['alg' => 'HS256', 'b64' => true]));
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'signatures' => [
                ['protected' => $protectedAbsent, 'signature' => Base64Url::encode("\x00")],
                ['protected' => $protectedTrue, 'signature' => Base64Url::encode("\x00")],
            ],
        ]);

        try {
            JsonSerializer::deserialize($json);
            self::fail('Expected InvalidHeaderException');
        } catch (InvalidHeaderException $e) {
            self::assertStringContainsString('has absent', $e->getMessage());
            self::assertStringContainsString('has true', $e->getMessage());
        }
    }

    // --- member-shape refusals on the parse path ---

    public function testDeserializeRejectsEmptySignatureMember(): void
    {
        // An explicit empty-string `signature` is not a missing member but is
        // still invalid — readRequiredString demands a *non-empty* string.
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'protected' => Base64Url::encode('{"alg":"HS256"}'),
            'signature' => '',
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"signature".*must be a non-empty string/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonStringPayloadMember(): void
    {
        $json = Json::encode([
            'payload' => 123,
            'protected' => Base64Url::encode('{"alg":"HS256"}'),
            'signature' => Base64Url::encode("\x00"),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"payload" must be a string/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonStringProtectedMember(): void
    {
        // `protected`, when present, must be a string (readOptionalString).
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'protected' => 42,
            'signature' => Base64Url::encode("\x00"),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"protected".*must be a string when present/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonBase64UrlProtectedHeader(): void
    {
        // The `protected` segment must decode as base64url before it can be
        // JSON-parsed; invalid alphabet is a malformed JWS.
        $json = Json::encode([
            'payload' => Base64Url::encode('x'),
            'protected' => 'not valid base64url!!',
            'signature' => Base64Url::encode("\x00"),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        JsonSerializer::deserialize($json);
    }
}
