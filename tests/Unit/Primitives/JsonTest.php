<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Primitives;

use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\Utf8;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Json::class)]
#[UsesClass(Utf8::class)]
final class JsonTest extends TestCase
{
    public function testDecodesSimpleObject(): void
    {
        $bytes = '{"alg":"HS256","typ":"JWT"}';

        self::assertSame(
            ['alg' => 'HS256', 'typ' => 'JWT'],
            Json::decode($bytes),
        );
    }

    public function testDecodesNestedStructure(): void
    {
        $bytes = '{"a":{"b":[1,2,{"c":"d"}]},"e":true}';

        self::assertSame(
            ['a' => ['b' => [1, 2, ['c' => 'd']]], 'e' => true],
            Json::decode($bytes),
        );
    }

    public function testRejectsDuplicateKeyAtRoot(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/Duplicate JSON key "alg"/');

        Json::decode('{"alg":"HS256","alg":"none"}');
    }

    public function testNestedDuplicateKeysAreNotChecked(): void
    {
        // By design: the RFC 7519 §4 mitigation targets the root object,
        // where registered claims live and where smuggling attacks operate.
        // Nested objects are application data; the application validates
        // them. json_decode keeps the last duplicate silently, which is
        // documented behaviour.
        $decoded = Json::decode('{"outer":{"x":1,"x":2}}');

        self::assertSame(['outer' => ['x' => 2]], $decoded);
    }

    public function testRejectsDuplicateKeyAfterIntermediateContainer(): void
    {
        // Confirms the state machine correctly pops/pushes objects: a key
        // duplicated only at the outer level, separated by a closed inner
        // object, must still be caught.
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/Duplicate JSON key "k"/');

        Json::decode('{"k":1,"other":{"k":2},"k":3}');
    }

    public function testAllowsSameKeyNameInDifferentSiblingObjects(): void
    {
        // Two sibling objects each having a "k" is not a duplicate — only
        // repeats within the same object are.
        $decoded = Json::decode('{"a":{"k":1},"b":{"k":2}}');

        self::assertSame(['a' => ['k' => 1], 'b' => ['k' => 2]], $decoded);
    }

    public function testDuplicateKeyDetectionIsEscapeAware(): void
    {
        // The two keys are literally "a\"b" both times — escape handling
        // must not split them into different keys.
        $this->expectException(MalformedJwtException::class);

        Json::decode('{"a\"b":1,"a\"b":2}');
    }

    public function testQuoteInsideValueDoesNotConfuseKeyScanner(): void
    {
        // A value-string containing the same byte pattern as a key must not
        // trip duplicate detection.
        $decoded = Json::decode('{"k":"k","k2":"k"}');

        self::assertSame(['k' => 'k', 'k2' => 'k'], $decoded);
    }

    #[DataProvider('invalidRootProvider')]
    public function testRejectsNonObjectRoot(string $bytes): void
    {
        $this->expectException(MalformedJwtException::class);

        Json::decode($bytes);
    }

    /** @return iterable<string, array{string}> */
    public static function invalidRootProvider(): iterable
    {
        yield 'array root' => ['[1,2,3]'];
        yield 'string root' => ['"hello"'];
        yield 'number root' => ['42'];
        yield 'bool root' => ['true'];
        yield 'null root' => ['null'];
    }

    public function testRejectsMalformedJson(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/Invalid JSON/');

        Json::decode('{"alg":}');
    }

    public function testRejectsBomPrefixedJson(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/UTF-8/');

        Json::decode("\xEF\xBB\xBF" . '{"alg":"HS256"}');
    }

    public function testRejectsIllFormedUtf8(): void
    {
        $this->expectException(MalformedJwtException::class);

        Json::decode("\xC0\x80"); // overlong NUL
    }

    public function testEncodesObjectWithoutSlashEscaping(): void
    {
        // RFC 7515 examples don't escape slashes; preserving that produces
        // the canonical wire form.
        $encoded = Json::encode(['iss' => 'https://issuer.example/']);

        self::assertSame('{"iss":"https://issuer.example/"}', $encoded);
    }

    public function testAcceptsLeadingWhitespaceBeforeRootObject(): void
    {
        // JSON permits whitespace before the root value; the scanner must
        // skip it before checking that the root is `{`.
        $decoded = Json::decode("  \n\t{\"alg\":\"HS256\"}");

        self::assertSame(['alg' => 'HS256'], $decoded);
    }

    public function testRejectsAllWhitespaceInput(): void
    {
        // Pure-whitespace input has no root object; the scanner exits
        // cleanly and json_decode then rejects the document.
        $this->expectException(MalformedJwtException::class);

        Json::decode("   \n\t  ");
    }

    public function testDecodesObjectWithWhitespace(): void
    {
        // RFC 7515 §A.1 header is whitespace-bearing (`{"typ":"JWT",\r\n "alg":"HS256"}`);
        // the scanner must accept whitespace between tokens at any depth.
        $bytes = "{\n\t\"a\" : 1,\r\n  \"b\" : [\t 2 , 3 ]\n}";

        self::assertSame(['a' => 1, 'b' => [2, 3]], Json::decode($bytes));
    }

    public function testRejectsUnterminatedString(): void
    {
        // Exercises both the scanner's $len fallback in scanStringEnd and the
        // JsonException catch on a key that decode itself will refuse.
        $this->expectException(MalformedJwtException::class);

        Json::decode('{"key');
    }

    public function testEncodeRejectsInvalidUtf8(): void
    {
        // json_encode refuses ill-formed UTF-8 strings; Json::encode must
        // wrap that failure in MalformedJwtException rather than letting
        // the underlying JsonException leak.
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/Cannot encode/');

        Json::encode(['bad' => "\xC0\x80"]);
    }

    public function testEncodeDecodeRoundTrip(): void
    {
        $original = [
            'iss' => 'https://issuer.example',
            'aud' => ['a', 'b', 'c'],
            'exp' => 1_700_000_000,
            'nested' => ['k' => true],
        ];

        self::assertSame($original, Json::decode(Json::encode($original)));
    }
}
