<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwe;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jwe\CompactJwe;
use Medzuch\Jwt\Jwe\CompactSerializer;
use Medzuch\Jwt\Jwe\ParsedJwe;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\Utf8;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CompactSerializer::class)]
#[CoversClass(CompactJwe::class)]
#[CoversClass(ParsedJwe::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(Json::class)]
#[UsesClass(Utf8::class)]
final class CompactSerializerTest extends TestCase
{
    public function testSerializeProducesFiveDotSeparatedSegments(): void
    {
        $jwe = CompactSerializer::serialize(
            ['alg' => 'dir', 'enc' => 'A128GCM'],
            'encrypted-key',
            "\x01\x02\x03",
            'cipher-bytes',
            "\xaa\xbb",
        );

        $segments = explode('.', $jwe->value);

        self::assertCount(5, $segments);
        self::assertNotSame('', $segments[0]);
        self::assertSame(Base64Url::encode('encrypted-key'), $segments[1]);
        self::assertSame(Base64Url::encode("\x01\x02\x03"), $segments[2]);
        self::assertSame(Base64Url::encode('cipher-bytes'), $segments[3]);
        self::assertSame(Base64Url::encode("\xaa\xbb"), $segments[4]);
    }

    public function testRoundTrip(): void
    {
        $header = ['alg' => 'A128KW', 'enc' => 'A128CBC-HS256', 'kid' => 'k1', 'typ' => 'JWT'];
        $encryptedKey = "\x10\x11\x12\x13";
        $iv = "\x20\x21\x22\x23";
        $ciphertext = 'the-ciphertext-bytes';
        $tag = "\x30\x31\x32\x33";

        $jwe = CompactSerializer::serialize($header, $encryptedKey, $iv, $ciphertext, $tag);
        $parsed = CompactSerializer::deserialize($jwe->value);

        self::assertSame($header, $parsed->header);
        self::assertSame($encryptedKey, $parsed->encryptedKey);
        self::assertSame($iv, $parsed->iv);
        self::assertSame($ciphertext, $parsed->ciphertext);
        self::assertSame($tag, $parsed->tag);
        self::assertSame(
            $jwe->value,
            implode('.', [
                $parsed->encodedHeader,
                $parsed->encodedEncryptedKey,
                $parsed->encodedIv,
                $parsed->encodedCiphertext,
                $parsed->encodedTag,
            ]),
        );
    }

    /**
     * `dir` and ECDH-ES direct key agreement ship no Encrypted Key, and an
     * empty plaintext yields an empty ciphertext — both segments may be empty
     * while the JWE is still well-formed.
     */
    public function testRoundTripWithEmptyEncryptedKeyAndCiphertext(): void
    {
        $header = ['alg' => 'dir', 'enc' => 'A256GCM'];

        $jwe = CompactSerializer::serialize($header, '', "\x01\x02", '', "\x03\x04");
        $parsed = CompactSerializer::deserialize($jwe->value);

        self::assertSame('', $parsed->encryptedKey);
        self::assertSame('', $parsed->ciphertext);
        self::assertSame('', $parsed->encodedEncryptedKey);
        self::assertSame('', $parsed->encodedCiphertext);
        self::assertSame($header, $parsed->header);
    }

    public function testAdditionalAuthenticatedDataIsTheEncodedHeaderSegment(): void
    {
        $jwe = CompactSerializer::serialize(['alg' => 'dir', 'enc' => 'A128GCM'], '', 'iv', 'ct', 'tag');
        $parsed = CompactSerializer::deserialize($jwe->value);

        self::assertSame($parsed->encodedHeader, $parsed->additionalAuthenticatedData());
        self::assertSame(Base64Url::encode(Json::encode(['alg' => 'dir', 'enc' => 'A128GCM'])), $parsed->additionalAuthenticatedData());
    }

    public function testCompactJweIsStringable(): void
    {
        $jwe = new CompactJwe('a.b.c.d.e');

        self::assertSame('a.b.c.d.e', (string) $jwe);
        self::assertSame('a.b.c.d.e', $jwe->value);
    }

    public function testDeserializeRejectsEmptyString(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/empty/');

        CompactSerializer::deserialize('');
    }

    public function testDeserializeRejectsThreeSegments(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/exactly 5.*got 3/');

        CompactSerializer::deserialize('a.b.c');
    }

    public function testDeserializeRejectsSixSegments(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/exactly 5.*got 6/');

        CompactSerializer::deserialize('a.b.c.d.e.f');
    }

    public function testDeserializeRejectsEmptyHeaderSegment(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/header segment is empty/');

        CompactSerializer::deserialize($this->compact(''));
    }

    public function testDeserializeRejectsEmptyIvSegment(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/initialization vector segment is empty/');

        CompactSerializer::deserialize($this->compact($this->header(), encodedIv: ''));
    }

    public function testDeserializeRejectsEmptyTagSegment(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/authentication tag segment is empty/');

        CompactSerializer::deserialize($this->compact($this->header(), encodedTag: ''));
    }

    public function testDeserializeRejectsNonBase64UrlHeader(): void
    {
        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/not valid base64url/');

        CompactSerializer::deserialize($this->compact('not base64!'));
    }

    public function testDeserializeRejectsHeaderThatIsNotJsonObject(): void
    {
        $this->expectException(MalformedJwtException::class);

        CompactSerializer::deserialize($this->compact(Base64Url::encode('"a string"')));
    }

    public function testDeserializeRejectsHeaderMissingAlg(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/missing required "alg"/');

        CompactSerializer::deserialize($this->compact($this->header('{"enc":"A128GCM"}')));
    }

    public function testDeserializeRejectsHeaderMissingEnc(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/missing required "enc"/');

        CompactSerializer::deserialize($this->compact($this->header('{"alg":"dir"}')));
    }

    public function testDeserializeRejectsNonStringAlg(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"alg".*non-empty string/');

        CompactSerializer::deserialize($this->compact($this->header('{"alg":42,"enc":"A128GCM"}')));
    }

    public function testDeserializeRejectsEmptyEnc(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"enc".*non-empty string/');

        CompactSerializer::deserialize($this->compact($this->header('{"alg":"dir","enc":""}')));
    }

    public function testDeserializeRejectsCritPresent(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"crit".*RFC 7516/');

        CompactSerializer::deserialize($this->compact($this->header('{"alg":"dir","enc":"A128GCM","crit":["b64"]}')));
    }

    /**
     * Regression: an explicit JSON `null` for `crit` must still be refused —
     * `array_key_exists` catches it where `isset` would treat it as absent.
     */
    public function testDeserializeRejectsExplicitNullCrit(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"crit"/');

        CompactSerializer::deserialize($this->compact($this->header('{"alg":"dir","enc":"A128GCM","crit":null}')));
    }

    public function testDeserializeRejectsZipPresent(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"zip".*RFC 8725/');

        CompactSerializer::deserialize($this->compact($this->header('{"alg":"dir","enc":"A128GCM","zip":"DEF"}')));
    }

    public function testDeserializeRejectsNonStringTyp(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"typ".*string/');

        CompactSerializer::deserialize($this->compact($this->header('{"alg":"dir","enc":"A128GCM","typ":42}')));
    }

    public function testDeserializeRejectsExplicitNullCty(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"cty".*string/');

        CompactSerializer::deserialize($this->compact($this->header('{"alg":"dir","enc":"A128GCM","cty":null}')));
    }

    public function testDeserializeRejectsNonStringKid(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"kid".*string/');

        CompactSerializer::deserialize($this->compact($this->header('{"alg":"dir","enc":"A128GCM","kid":42}')));
    }

    private function header(string $json = '{"alg":"dir","enc":"A128GCM"}'): string
    {
        return Base64Url::encode($json);
    }

    /**
     * Assemble a five-segment compact JWE from an already-encoded header,
     * with valid non-empty base64url defaults for the other four segments.
     */
    private function compact(
        string $encodedHeader,
        string $encodedEncryptedKey = 'ZWs',
        string $encodedIv = 'aXY',
        string $encodedCiphertext = 'Y3Q',
        string $encodedTag = 'dGFn',
    ): string {
        return implode('.', [$encodedHeader, $encodedEncryptedKey, $encodedIv, $encodedCiphertext, $encodedTag]);
    }
}
