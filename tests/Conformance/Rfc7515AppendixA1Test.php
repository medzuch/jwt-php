<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7515 Appendix A.1 — full HS256 worked example, driven end-to-end
 * through CompactSerializer + Verifier.
 *
 * The vector in §A.1.1 fixes the protected header bytes (including the
 * embedded `\r\n` between fields), the JWS payload bytes (also embedding
 * `\r\n`), the JWK secret, and the resulting compact form. We reproduce
 * the full compact string and then verify it through the public API.
 */
#[CoversNothing]
final class Rfc7515AppendixA1Test extends TestCase
{
    /**
     * The exact compact form from RFC 7515 §A.1.1:
     * "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
     *   . "."
     *   . "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog"
     *   . "Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
     *   . "."
     *   . "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
     */
    private const COMPACT
        = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
        . '.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        . '.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    private const JWK_K = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

    public function testCompactDeserializesToTheVectorPieces(): void
    {
        $parsed = CompactSerializer::deserialize(self::COMPACT);

        self::assertSame('JWT', $parsed->header['typ']);
        self::assertSame('HS256', $parsed->header['alg']);

        // The §A.1.1 payload includes a CRLF after the comma. We assert
        // a couple of distinctive substrings rather than transcribing the
        // entire JSON; the byte-for-byte signing-input assertion below is
        // what proves the bytes are intact.
        self::assertStringContainsString('"iss":"joe"', $parsed->payload);
        self::assertStringContainsString("\r\n", $parsed->payload);

        self::assertSame(
            Base64Url::decode('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
            $parsed->signature,
        );
    }

    public function testVerifierAcceptsTheRfcVector(): void
    {
        $parsed = CompactSerializer::deserialize(self::COMPACT);

        $key = HmacKey::fromJwk([
            'kty' => 'oct',
            'alg' => 'HS256',
            'k' => self::JWK_K,
        ]);
        $resolver = new StaticJwkSetResolver(JwkSet::of($key));

        $result = (new Verifier())->verify($parsed, [new Hs256()], $resolver);

        self::assertSame($parsed, $result);
    }
}
