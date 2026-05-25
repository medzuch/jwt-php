<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Signing\Es512;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7520 §4.3 — ECDSA P-521 SHA-512 (ES512) signature, JOSE Cookbook.
 *
 * Uses the §3.2 EC key and the §4 common payload. As with the RFC 7515
 * §A.3 ES256 example, ECDSA is non-deterministic — we cannot reproduce
 * the cookbook's exact signature — so we exercise both halves:
 *   1. Verify the RFC's published compact form with the §3.2 public key
 *      (covers Verifier accepting a third-party P-521 signature).
 *   2. Re-sign the §4 payload with the §3.2 private key and verify it
 *      round-trips (covers Signer → DER → JOSE → Verifier for ES512).
 */
#[CoversNothing]
final class Rfc7520Section43Test extends TestCase
{
    private const KID = 'bilbo.baggins@hobbiton.example';

    /** Base64url-encoded §4 common payload. */
    private const ENCODED_PAYLOAD
        = 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXI'
        . 'gZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIH'
        . 'lvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';

    /** Compact Serialization from RFC 7520 §4.3.3. */
    private const COMPACT
        = 'eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9'
        . '.' . self::ENCODED_PAYLOAD
        . '.AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KR'
        . 'TzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IE'
        . 'KBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2';

    /**
     * The §3.2 EC key. `alg: ES512` is injected because this library binds
     * every key to one algorithm (RFC 7517 §4.4); the cookbook JWK omits it.
     *
     * @return array<string, string>
     */
    private static function jwk(): array
    {
        return [
            'kty' => 'EC',
            'alg' => 'ES512',
            'kid' => self::KID,
            'crv' => 'P-521',
            'x' => 'AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt',
            'y' => 'AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1',
            'd' => 'AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt',
        ];
    }

    public function testVerifierAcceptsTheRfcVector(): void
    {
        $parsed = CompactSerializer::deserialize(self::COMPACT);

        $result = (new Verifier())->verify($parsed, [new Es512()], $this->publicResolver());

        self::assertSame($parsed, $result);
    }

    public function testSignerProducesSignatureThatRoundTripsThroughVerifier(): void
    {
        $payload = Base64Url::decode(self::ENCODED_PAYLOAD);
        $private = EcPrivateKey::fromJwk(self::jwk());

        $jws = (new Signer())->sign(new Es512(), ['alg' => 'ES512', 'kid' => self::KID], $payload, $private);
        $parsed = CompactSerializer::deserialize($jws->value);

        // P-521 raw signature is exactly 2 × 66 bytes (RFC 7518 §3.4).
        self::assertSame(132, strlen($parsed->signature));
        self::assertSame($payload, $parsed->payload);

        self::assertSame($parsed, (new Verifier())->verify($parsed, [new Es512()], $this->publicResolver()));
    }

    private function publicResolver(): StaticJwkSetResolver
    {
        $jwk = self::jwk();
        unset($jwk['d']);

        return new StaticJwkSetResolver(JwkSet::of(EcPublicKey::fromJwk($jwk)));
    }
}
