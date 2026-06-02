<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7797 Appendix A.1 — JWS with unencoded payload, HS256, payload `$.02`.
 *
 * The example exercises the corner that makes RFC 7797 §5.2 SHOULD-advise
 * detached or JSON serialization for non-detached unencoded payloads: the
 * payload itself contains a `.` character, so the compact form has four
 * dot-separated segments and the recipient must split on first-and-last
 * `.` to recover header / payload / signature.
 *
 * The published token verifies under the key in the appendix, and our own
 * Signer emits the identical bytes from the same inputs.
 */
#[CoversNothing]
final class Rfc7797AppendixA1Test extends TestCase
{
    /** RFC 7797 §A.1 — the published HMAC key (`k` is base64url of 64 bytes). */
    private const KEY_K = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

    /** RFC 7797 §4.1 — header bytes that go on the wire before base64url. */
    private const ENCODED_HEADER = 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19';

    /** The literal payload bytes (note the `.`). */
    private const PAYLOAD = '$.02';

    /** RFC 7797 §4.1 — the published signature. */
    private const ENCODED_SIGNATURE = 'A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY';

    private const PUBLISHED_TOKEN
        = self::ENCODED_HEADER . '.' . self::PAYLOAD . '.' . self::ENCODED_SIGNATURE;

    public function testPublishedTokenVerifies(): void
    {
        $key = HmacKey::fromBinary(Base64Url::decode(self::KEY_K), 'HS256', kid: 'rfc7797');

        $parsed = CompactSerializer::deserialize(self::PUBLISHED_TOKEN);

        // The structural parse must surface the on-the-wire fields without
        // re-encoding: the published signature feeds the verifier verbatim.
        self::assertSame(self::ENCODED_HEADER, $parsed->encodedHeader);
        self::assertSame(self::PAYLOAD, $parsed->encodedPayload);
        self::assertSame(self::PAYLOAD, $parsed->payload);
        self::assertSame(self::ENCODED_SIGNATURE, $parsed->encodedSignature);

        $verified = (new Verifier())->verify(
            $parsed,
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($key)),
        );

        self::assertSame(self::PAYLOAD, $verified->payload);
    }

    public function testSignerReproducesPublishedToken(): void
    {
        $key = HmacKey::fromBinary(Base64Url::decode(self::KEY_K), 'HS256', kid: 'rfc7797');

        // Order-insensitive: the canonical form RFC 7797 §A.1 prints has
        // alg, b64, crit in that order, which matches what Signer emits
        // when alg is inserted last by withAlg (kept first via key order
        // preservation in PHP arrays).
        $signed = (new Signer())->sign(
            new Hs256(),
            ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']],
            self::PAYLOAD,
            $key,
        );

        self::assertSame(self::PUBLISHED_TOKEN, $signed->value);
    }

    public function testDetachedFormVerifies(): void
    {
        $key = HmacKey::fromBinary(Base64Url::decode(self::KEY_K), 'HS256', kid: 'rfc7797');

        // Same signing input → same signature, regardless of whether the
        // payload travels on the wire (RFC 7515 Appendix F).
        $detached = (new Signer())->sign(
            new Hs256(),
            ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']],
            self::PAYLOAD,
            $key,
            detached: true,
        );

        self::assertSame(self::ENCODED_HEADER . '..' . self::ENCODED_SIGNATURE, $detached->value);

        $parsed = CompactSerializer::deserialize($detached->value);
        $verified = (new Verifier())->verifyDetached(
            $parsed,
            self::PAYLOAD,
            [new Hs256()],
            new StaticJwkSetResolver(JwkSet::of($key)),
        );

        self::assertSame(self::PAYLOAD, $verified->payload);
    }
}
