<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Signing\EdDsa;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\OkpPrivateKey;
use Medzuch\Jwt\Key\OkpPublicKey;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8037 Appendix A — Ed25519 worked example.
 *
 * Ed25519 is deterministic (RFC 8032 §5.1.6), so unlike ECDSA we can
 * assert byte-for-byte equality with the appendix's published signature
 * and compact form. This covers both halves of the algorithm:
 *
 *   §A.1 — Ed25519 keypair (public + private seed).
 *   §A.4 — JWS using Ed25519 (signing input + signature).
 *   §A.5 — verification of the same signature.
 */
#[CoversNothing]
final class Rfc8037AppendixATest extends TestCase
{
    /**
     * RFC 8037 §A.1 — public coordinate `x` and private seed `d`.
     */
    private const X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';

    private const D = 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A';

    /**
     * RFC 8037 §A.4 — protected header, payload, signing input, signature.
     */
    private const HEADER_JSON = '{"alg":"EdDSA"}';

    private const PAYLOAD = 'Example of Ed25519 signing';

    private const SIGNING_INPUT = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';

    private const SIGNATURE_B64URL = 'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg';

    private const COMPACT = self::SIGNING_INPUT . '.' . self::SIGNATURE_B64URL;

    /** @return array<string, string> */
    private static function privJwk(): array
    {
        return [
            'kty' => 'OKP',
            'alg' => 'EdDSA',
            'crv' => 'Ed25519',
            'x' => self::X,
            'd' => self::D,
        ];
    }

    /** @return array<string, string> */
    private static function pubJwk(): array
    {
        $jwk = self::privJwk();
        unset($jwk['d']);

        return $jwk;
    }

    public function testSignerReproducesTheVectorByteForByte(): void
    {
        $private = OkpPrivateKey::fromJwk(self::privJwk());

        $jws = (new Signer())->sign(new EdDsa(), ['alg' => 'EdDSA'], self::PAYLOAD, $private);

        self::assertSame(self::COMPACT, $jws->value);

        $parsed = CompactSerializer::deserialize($jws->value);

        self::assertSame(Base64Url::decode(self::SIGNATURE_B64URL), $parsed->signature);
        self::assertSame(self::PAYLOAD, $parsed->payload);
        self::assertSame('EdDSA', $parsed->header['alg']);
        self::assertSame(self::HEADER_JSON, json_encode($parsed->header));
    }

    public function testVerifierAcceptsTheRfcVector(): void
    {
        $parsed = CompactSerializer::deserialize(self::COMPACT);

        $resolver = new StaticJwkSetResolver(JwkSet::of(OkpPublicKey::fromJwk(self::pubJwk())));

        $result = (new Verifier())->verify($parsed, [new EdDsa()], $resolver);

        self::assertSame($parsed, $result);
    }
}
