<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Exception\AlgorithmNotAllowedException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

use function hash_hmac;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;

use const OPENSSL_KEYTYPE_RSA;

/**
 * The McLean algorithm-confusion attack (RFC 8725 §2.1).
 *
 * Setup: a server issues RS256-signed tokens. An attacker takes a
 * legitimate token, rewrites the protected header's `alg` to `HS256`,
 * and produces a new "signature" by computing HMAC-SHA-256 over the
 * tampered signing input **using the server's RSA public key bytes as
 * the HMAC secret**. A naive library that picks the verification
 * algorithm from the header — and looks up "the key" by `kid` — would
 * then verify the forged token successfully, because both sides do the
 * same HMAC computation.
 *
 * This library refuses the attack at multiple layers. The two scenarios
 * below cover the two interesting cases:
 *
 *   - Caller only allowed RS256: the allowlist alone refuses HS256.
 *   - Caller allowed both RS256 and HS256: the type system + key/alg
 *     binding refuses the cross-class use because `Hs256::verify`
 *     accepts only an `HmacKey`, and the resolver returns an
 *     `RsaPublicKey`.
 *
 * The roadmap exit criterion for Phase 1 is that this PoC throws
 * `KeyMismatchException`; we additionally exercise the allowlist-only
 * path because that is the path real callers will be on.
 */
#[CoversNothing]
final class AlgorithmConfusionMcleanPocTest extends TestCase
{
    /** @var array{public_pem: string, public_key: RsaPublicKey, private_key: RsaPrivateKey} */
    private static array $keys;

    public static function setUpBeforeClass(): void
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource);

        $privatePem = '';
        openssl_pkey_export($resource, $privatePem);

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        /** @var string $publicPem */
        $publicPem = $details['key'];

        self::$keys = [
            'public_pem' => $publicPem,
            'public_key' => RsaPublicKey::fromPem($publicPem, 'RS256', kid: 'server-2026'),
            'private_key' => RsaPrivateKey::fromPem($privatePem, 'RS256', kid: 'server-2026'),
        ];
    }

    /**
     * Caller-side allowlist contains only RS256 (the realistic posture).
     * The forged HS256 token is refused by {@see Verifier} before any key
     * is even resolved.
     */
    public function testForgedHs256TokenRefusedByAllowlist(): void
    {
        $forged = self::forgeHs256TokenSignedWithPublicKey();
        $parsed = CompactSerializer::deserialize($forged);

        $resolver = new StaticJwkSetResolver(JwkSet::of(self::$keys['public_key']));

        $this->expectException(AlgorithmNotAllowedException::class);
        $this->expectExceptionMessageMatches('/"HS256".*allowlist \[RS256\].*RFC 8725 §3\.1/');

        (new Verifier())->verify($parsed, [new Rs256()], $resolver);
    }

    /**
     * Caller-side allowlist (incorrectly) includes BOTH RS256 and HS256.
     * The resolver returns the RSA public key (because that is the `kid`
     * the attacker copied). `Hs256::verify` is asked to verify with an
     * `RsaPublicKey`, which it refuses via instanceof — this is the
     * roadmap's exit-criterion path.
     */
    public function testForgedHs256TokenRefusedByKeyClassBinding(): void
    {
        $forged = self::forgeHs256TokenSignedWithPublicKey();
        $parsed = CompactSerializer::deserialize($forged);

        $resolver = new StaticJwkSetResolver(JwkSet::of(self::$keys['public_key']));

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/McLean confusion/');

        (new Verifier())->verify($parsed, [new Rs256(), new Hs256()], $resolver);
    }

    /**
     * Sanity check: the legitimately-issued RS256 token verifies fine.
     */
    public function testLegitimateRs256TokenVerifies(): void
    {
        $legitimate = (new Signer())->sign(
            new Rs256(),
            ['kid' => 'server-2026'],
            '{"sub":"user-1"}',
            self::$keys['private_key'],
        );

        $parsed = CompactSerializer::deserialize($legitimate->value);
        $resolver = new StaticJwkSetResolver(JwkSet::of(self::$keys['public_key']));

        $result = (new Verifier())->verify($parsed, [new Rs256()], $resolver);

        self::assertSame($parsed, $result);
    }

    /**
     * Reproduce the attacker's construction: take the header `{"alg":"HS256","kid":"server-2026"}`,
     * pick a payload, base64url-encode both, and sign the signing input
     * with HMAC-SHA-256 keyed by the server's PEM bytes.
     */
    private static function forgeHs256TokenSignedWithPublicKey(): string
    {
        $header = ['alg' => 'HS256', 'kid' => 'server-2026'];
        $payload = '{"sub":"user-1","attacker":"controls-everything"}';

        $encodedHeader = Base64Url::encode(Json::encode($header));
        $encodedPayload = Base64Url::encode($payload);
        $signingInput = $encodedHeader . '.' . $encodedPayload;

        // The attacker uses whatever bytes they can guess for the
        // "public key" — typically the PEM string as served. The point
        // is that those bytes are *known to the attacker* and they can
        // produce a valid MAC over the tampered token. We replicate the
        // worst case here.
        $forgedSignature = hash_hmac('sha256', $signingInput, self::$keys['public_pem'], true);

        return $signingInput . '.' . Base64Url::encode($forgedSignature);
    }
}
