<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Signing\Es256;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7515 Appendix A.3 — ECDSA P-256 SHA-256 worked example.
 *
 * ECDSA picks a fresh nonce on every sign, so we cannot reproduce the
 * RFC's compact form byte-for-byte. Instead we exercise both halves:
 *   1. Re-sign the §A.3.1 input with the §A.3.1 private key and verify
 *      that our own signature round-trips through Verifier (covers Signer
 *      → DER → JOSE → Verifier).
 *   2. Verify the RFC's exact compact form using the §A.3.1 public key
 *      (covers Verifier accepting a third-party signature).
 */
#[CoversNothing]
final class Rfc7515AppendixA3Test extends TestCase
{
    /**
     * Compact form from RFC 7515 §A.3.1.
     */
    private const COMPACT
        = 'eyJhbGciOiJFUzI1NiJ9'
        . '.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        . '.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';

    /** @return array<string, string> */
    private static function jwk(): array
    {
        // The JWK from RFC 7515 §A.3.1. `alg: ES256` is injected because
        // this library requires the alg binding on every key (RFC 7517 §4.4);
        // the RFC's example JWK does not include it.
        return [
            'kty' => 'EC',
            'alg' => 'ES256',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ];
    }

    public function testSignerProducesSignatureThatRoundTripsThroughVerifier(): void
    {
        // ECDSA is non-deterministic: the RFC's signature in §A.3.1 was
        // produced with a specific nonce and we cannot reproduce it. What
        // we *can* assert is that a signature we produce here verifies
        // against the same public key — i.e., DER↔JOSE plumbing is correct.
        $payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
        $private = EcPrivateKey::fromJwk(self::jwk());

        $jws = (new Signer())->sign(new Es256(), ['alg' => 'ES256'], $payload, $private);

        // Signature is exactly 2 × 32 bytes for P-256 (RFC 7518 §3.4).
        $parsed = CompactSerializer::deserialize($jws->value);
        self::assertSame(64, strlen($parsed->signature));
        self::assertSame($payload, $parsed->payload);
        self::assertSame('ES256', $parsed->header['alg']);

        // Header bytes are exactly `{"alg":"ES256"}` — no whitespace, no `typ`.
        self::assertSame('{"alg":"ES256"}', json_encode($parsed->header));

        // The signature we just produced must verify under the public key.
        $jwk = self::jwk();
        unset($jwk['d']);
        $resolver = new StaticJwkSetResolver(JwkSet::of(EcPublicKey::fromJwk($jwk)));

        self::assertSame($parsed, (new Verifier())->verify($parsed, [new Es256()], $resolver));
    }

    public function testVerifierAcceptsTheRfcVector(): void
    {
        $parsed = CompactSerializer::deserialize(self::COMPACT);

        $jwk = self::jwk();
        unset($jwk['d']);

        $resolver = new StaticJwkSetResolver(JwkSet::of(EcPublicKey::fromJwk($jwk)));

        $result = (new Verifier())->verify($parsed, [new Es256()], $resolver);

        self::assertSame($parsed, $result);
    }
}
