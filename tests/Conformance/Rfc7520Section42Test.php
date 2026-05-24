<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Signing\Ps384;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Key\RsaPublicKey;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7520 §4.2 — RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
 *
 * PSS picks a fresh random salt for every signature (RFC 8017 §9.1.1
 * step 3), so unlike deterministic schemes we cannot reproduce the
 * RFC's compact form byte-for-byte. The conformance bar therefore is:
 * **the Verifier accepts the RFC's exact compact form** under the §3.4
 * public key.
 *
 * The sign-and-roundtrip path is covered separately in
 * {@see \Medzuch\Jwt\Tests\Unit\Algorithm\Signing\PssSigningAlgorithmTest}
 * using a freshly generated key plus an `openssl dgst` cross-validation —
 * a stronger conformance assertion than reusing the RFC's stored CRT
 * components, which OpenSSL 3.x rejects on consistency grounds for
 * some published 2016-era JWKs (this one included).
 */
#[CoversNothing]
final class Rfc7520Section42Test extends TestCase
{
    /**
     * Compact form from RFC 7520 §4.2.3 (Figure 26).
     */
    private const COMPACT
        = 'eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9'
        . '.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4'
        . '.cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw';

    /** @return array<string, string> */
    private static function pubJwk(): array
    {
        // RFC 7520 §3.4 — Figure 18 (public half only). `alg: PS384` is
        // injected because this library requires the alg binding on every
        // key (RFC 7517 §4.4); the RFC's example JWK does not include it.
        return [
            'kty' => 'RSA',
            'alg' => 'PS384',
            'kid' => 'bilbo.baggins@hobbiton.example',
            'n' => 'n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw',
            'e' => 'AQAB',
        ];
    }

    public function testVerifierAcceptsTheRfcVector(): void
    {
        $parsed = CompactSerializer::deserialize(self::COMPACT);

        $resolver = new StaticJwkSetResolver(JwkSet::of(RsaPublicKey::fromJwk(self::pubJwk())));

        $result = (new Verifier())->verify($parsed, [new Ps384()], $resolver);

        self::assertSame($parsed, $result);
    }
}
