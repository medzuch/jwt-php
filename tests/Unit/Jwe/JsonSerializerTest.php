<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwe;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jwe\FlattenedJwe;
use Medzuch\Jwt\Jwe\GeneralJwe;
use Medzuch\Jwt\Jwe\Internal\JweHeader;
use Medzuch\Jwt\Jwe\JsonSerializer;
use Medzuch\Jwt\Jwe\ParsedJwe;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\Utf8;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(JsonSerializer::class)]
#[CoversClass(FlattenedJwe::class)]
#[CoversClass(GeneralJwe::class)]
#[UsesClass(ParsedJwe::class)]
#[UsesClass(JweHeader::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(Json::class)]
#[UsesClass(Utf8::class)]
final class JsonSerializerTest extends TestCase
{
    private const IV = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b";
    private const TAG = "\x10\x11\x12\x13\x14\x15\x16\x17";

    public function testFlattenedRoundTrip(): void
    {
        $protected = ['alg' => 'A128KW', 'enc' => 'A128CBC-HS256', 'kid' => 'k1'];

        $jwe = JsonSerializer::serializeFlattened($protected, [], [], 'wrapped-key', self::IV, 'cipher', self::TAG);
        $parsed = JsonSerializer::deserialize($jwe->value);

        self::assertSame($protected, $parsed->header);
        self::assertSame('wrapped-key', $parsed->encryptedKey);
        self::assertSame(self::IV, $parsed->iv);
        self::assertSame('cipher', $parsed->ciphertext);
        self::assertSame(self::TAG, $parsed->tag);
        self::assertNull($parsed->aad);
        // No JWE AAD → AAD is the encoded protected header alone.
        self::assertSame($parsed->encodedHeader, $parsed->additionalAuthenticatedData());
        self::assertSame(Base64Url::encode(Json::encode($protected)), $parsed->encodedHeader);
    }

    public function testFlattenedHasNoRecipientsArrayAndHoistsRecipientMembers(): void
    {
        $jwe = JsonSerializer::serializeFlattened(
            ['alg' => 'A128KW', 'enc' => 'A128GCM'],
            ['cty' => 'JWT'],
            ['kid' => 'k1'],
            'wrapped',
            self::IV,
            'ct',
            self::TAG,
        );

        $decoded = Json::decode($jwe->value);

        self::assertArrayNotHasKey('recipients', $decoded);
        self::assertSame(['kid' => 'k1'], $decoded['header']);
        self::assertSame(['cty' => 'JWT'], $decoded['unprotected']);
        self::assertSame(Base64Url::encode('wrapped'), $decoded['encrypted_key']);
    }

    public function testGeneralRoundTripWrapsTheRecipientInAnArray(): void
    {
        $protected = ['alg' => 'A256KW', 'enc' => 'A256GCM'];

        $jwe = JsonSerializer::serializeGeneral($protected, [], ['kid' => 'k1'], 'wrapped-key', self::IV, 'cipher', self::TAG);

        $decoded = Json::decode($jwe->value);
        self::assertIsArray($decoded['recipients']);
        self::assertCount(1, $decoded['recipients']);
        self::assertSame(['header' => ['kid' => 'k1'], 'encrypted_key' => Base64Url::encode('wrapped-key')], $decoded['recipients'][0]);

        $parsed = JsonSerializer::deserialize($jwe->value);
        self::assertSame(['alg' => 'A256KW', 'enc' => 'A256GCM', 'kid' => 'k1'], $parsed->header);
        self::assertSame('wrapped-key', $parsed->encryptedKey);
    }

    /**
     * `dir` ships no Encrypted Key and may carry no per-recipient header — the
     * recipient is then an empty JSON *object*, not the array `[]`.
     */
    public function testGeneralEmptyRecipientIsAnObjectNotAnArray(): void
    {
        $jwe = JsonSerializer::serializeGeneral(['alg' => 'dir', 'enc' => 'A128GCM'], [], [], '', self::IV, 'ct', self::TAG);

        self::assertStringContainsString('"recipients":[{}]', $jwe->value);

        $parsed = JsonSerializer::deserialize($jwe->value);
        self::assertSame('', $parsed->encryptedKey);
        self::assertSame(['alg' => 'dir', 'enc' => 'A128GCM'], $parsed->header);
    }

    public function testAadFoldsIntoAuthenticatedData(): void
    {
        $aad = 'extra-authenticated-data';
        $jwe = JsonSerializer::serializeFlattened(['alg' => 'dir', 'enc' => 'A128GCM'], [], [], '', self::IV, 'ct', self::TAG, $aad);

        $decoded = Json::decode($jwe->value);
        self::assertSame(Base64Url::encode($aad), $decoded['aad']);

        $parsed = JsonSerializer::deserialize($jwe->value);
        self::assertSame(Base64Url::encode($aad), $parsed->aad);
        self::assertSame(
            $parsed->encodedHeader . '.' . Base64Url::encode($aad),
            $parsed->additionalAuthenticatedData(),
        );
    }

    /**
     * §5.12-style JWE: no protected header at all; `alg`/`enc` arrive via the
     * shared unprotected header and the AAD is computed over the empty string.
     */
    public function testAbsentProtectedHeader(): void
    {
        $jwe = JsonSerializer::serializeFlattened([], ['alg' => 'dir', 'enc' => 'A128GCM'], [], '', self::IV, 'ct', self::TAG);

        $decoded = Json::decode($jwe->value);
        self::assertArrayNotHasKey('protected', $decoded);

        $parsed = JsonSerializer::deserialize($jwe->value);
        self::assertSame('', $parsed->encodedHeader);
        self::assertSame('', $parsed->additionalAuthenticatedData());
        self::assertSame(['alg' => 'dir', 'enc' => 'A128GCM'], $parsed->header);
    }

    public function testEffectiveHeaderIsTheUnionOfAllThreeSources(): void
    {
        $parsed = JsonSerializer::deserialize(JsonSerializer::serializeGeneral(
            ['enc' => 'A128GCM'],
            ['alg' => 'A128KW'],
            ['kid' => 'k1'],
            'wrapped',
            self::IV,
            'ct',
            self::TAG,
        )->value);

        self::assertSame(['enc' => 'A128GCM', 'alg' => 'A128KW', 'kid' => 'k1'], $parsed->header);
    }

    public function testDtosAreStringable(): void
    {
        self::assertSame('{"a":1}', (string) new FlattenedJwe('{"a":1}'));
        self::assertSame('{"b":2}', (string) new GeneralJwe('{"b":2}'));
    }

    // --- disjointness ------------------------------------------------------

    /** @return iterable<string, array{array<string,mixed>, array<string,mixed>, array<string,mixed>, string}> */
    public static function overlappingHeaderProvider(): iterable
    {
        yield 'protected vs unprotected' => [['alg' => 'dir', 'enc' => 'A128GCM', 'kid' => 'a'], ['kid' => 'b'], [], 'protected and unprotected'];
        yield 'protected vs per-recipient' => [['alg' => 'dir', 'enc' => 'A128GCM', 'kid' => 'a'], [], ['kid' => 'b'], 'protected and per-recipient'];
        yield 'unprotected vs per-recipient' => [['alg' => 'dir', 'enc' => 'A128GCM'], ['kid' => 'a'], ['kid' => 'b'], 'unprotected and per-recipient'];
    }

    /**
     * @param array<string, mixed> $protected
     * @param array<string, mixed> $shared
     * @param array<string, mixed> $perRecipient
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('overlappingHeaderProvider')]
    public function testSerializeRejectsOverlappingHeaderNames(array $protected, array $shared, array $perRecipient, string $where): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches(sprintf('/disjoint.*"kid".*%s/', preg_quote($where, '/')));

        JsonSerializer::serializeFlattened($protected, $shared, $perRecipient, '', self::IV, 'ct', self::TAG);
    }

    public function testDeserializeRejectsOverlappingHeaderNames(): void
    {
        $json = Json::encode([
            'protected' => Base64Url::encode(Json::encode(['alg' => 'dir', 'enc' => 'A128GCM', 'kid' => 'a'])),
            'unprotected' => ['kid' => 'b'],
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/disjoint/');

        JsonSerializer::deserialize($json);
    }

    // --- structural refusals ----------------------------------------------

    public function testDeserializeRejectsNonObjectRoot(): void
    {
        $this->expectException(MalformedJwtException::class);

        JsonSerializer::deserialize('"a string"');
    }

    public function testDeserializeRejectsMissingCiphertext(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'iv' => Base64Url::encode(self::IV),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/missing required "ciphertext"/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsMissingIv(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/missing required "iv"/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsEmptyTag(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => '',
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"tag".*must not be empty/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonStringProtected(): void
    {
        $json = Json::encode([
            'protected' => ['not' => 'a string'],
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"protected".*must be a string/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonObjectUnprotected(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'unprotected' => 'nope',
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"unprotected".*must be a JSON object/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonStringEncryptedKey(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'encrypted_key' => 123,
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"encrypted_key".*must be a string/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsListAsHeader(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'header' => ['a', 'b'],
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"header".*must be a JSON object/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsMixingRecipientsWithFlattenedMembers(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'encrypted_key' => Base64Url::encode('wrapped'),
            'recipients' => [['encrypted_key' => Base64Url::encode('wrapped')]],
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/mixes the general "recipients".*flattened/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsEmptyRecipientsArray(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'recipients' => [],
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"recipients" must be a non-empty array/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonArrayRecipients(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'recipients' => ['not' => 'a list'],
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"recipients" must be a non-empty array/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsMultipleRecipients(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'recipients' => [
                ['encrypted_key' => Base64Url::encode('one')],
                ['encrypted_key' => Base64Url::encode('two')],
            ],
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/multiple recipients \(2\) is not supported/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonObjectRecipientEntry(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'recipients' => ['plain string'],
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/"recipients" entry must be a JSON object/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonBase64UrlIv(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'iv' => 'not base64!',
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/initialization vector is not valid base64url/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonBase64UrlProtectedHeader(): void
    {
        $json = Json::encode([
            'protected' => 'not base64!',
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/protected header is not valid base64url/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsNonBase64UrlAad(): void
    {
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'aad' => 'not base64!',
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/additional authenticated data is not valid base64url/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsEffectiveHeaderMissingAlg(): void
    {
        $json = Json::encode([
            'protected' => Base64Url::encode(Json::encode(['enc' => 'A128GCM'])),
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/missing required "alg"/');

        JsonSerializer::deserialize($json);
    }

    public function testDeserializeRejectsCritInUnprotectedHeader(): void
    {
        // `crit` is refused wherever it appears, not just in the protected
        // header — the JSON serialization offers no escape hatch.
        $json = Json::encode([
            'protected' => $this->protectedHeader(),
            'unprotected' => ['crit' => ['exp']],
            'iv' => Base64Url::encode(self::IV),
            'ciphertext' => Base64Url::encode('ct'),
            'tag' => Base64Url::encode(self::TAG),
        ]);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"crit"/');

        JsonSerializer::deserialize($json);
    }

    private function protectedHeader(string $json = '{"alg":"dir","enc":"A128GCM"}'): string
    {
        return Base64Url::encode($json);
    }
}
