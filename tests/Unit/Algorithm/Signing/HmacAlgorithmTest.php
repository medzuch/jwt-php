<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\Signing;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Hs384;
use Medzuch\Jwt\Algorithm\Signing\Hs512;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\RsaKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\ConstantTime;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HmacAlgorithm::class)]
#[CoversClass(Hs256::class)]
#[CoversClass(Hs384::class)]
#[CoversClass(Hs512::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(ConstantTime::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
#[UsesClass(RsaKey::class)]
#[UsesClass(RsaPublicKey::class)]
#[UsesClass(RsaPrivateKey::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Rs256::class)]
final class HmacAlgorithmTest extends TestCase
{
    public function testHs256Identity(): void
    {
        $algo = new Hs256();

        self::assertSame('HS256', $algo->name());
        self::assertSame(AlgorithmFamily::Hmac, $algo->family());
    }

    public function testHs384Identity(): void
    {
        $algo = new Hs384();

        self::assertSame('HS384', $algo->name());
        self::assertSame(AlgorithmFamily::Hmac, $algo->family());
    }

    public function testHs512Identity(): void
    {
        $algo = new Hs512();

        self::assertSame('HS512', $algo->name());
        self::assertSame(AlgorithmFamily::Hmac, $algo->family());
    }

    /** @param int<1, max> $bytes */
    #[DataProvider('roundTripProvider')]
    public function testSignAndVerifyRoundTrip(HmacAlgorithm $algo, string $alg, int $bytes): void
    {
        $key = HmacKey::fromBinary(random_bytes($bytes), $alg);
        $input = 'jws.signing.input';

        $signature = $algo->sign($input, $key);

        self::assertTrue($algo->verify($input, $signature, $key));
    }

    /** @return iterable<string, array{HmacAlgorithm, string, int<1, max>}> */
    public static function roundTripProvider(): iterable
    {
        yield 'HS256' => [new Hs256(), 'HS256', 32];
        yield 'HS384' => [new Hs384(), 'HS384', 48];
        yield 'HS512' => [new Hs512(), 'HS512', 64];
    }

    public function testVerifyRejectsTamperedInput(): void
    {
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $signature = $algo->sign('original.input', $key);

        self::assertFalse($algo->verify('tampered.input', $signature, $key));
    }

    public function testVerifyRejectsTamperedSignature(): void
    {
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $signature = $algo->sign('input', $key);
        $tampered = $signature ^ str_repeat("\x01", 32);

        self::assertFalse($algo->verify('input', $tampered, $key));
    }

    /**
     * RFC 7515 Appendix A.1: HS256 worked example. Reproduces the JWK,
     * signing input, and expected signature byte-for-byte.
     */
    public function testRfc7515AppendixA1Vector(): void
    {
        $jwk = [
            'kty' => 'oct',
            'alg' => 'HS256',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ];

        $key = HmacKey::fromJwk($jwk);
        $algo = new Hs256();

        $signingInput
            = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
            . '.'
            . 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $expectedSignature = Base64Url::decode('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');

        $produced = $algo->sign($signingInput, $key);

        self::assertSame($expectedSignature, $produced);
        self::assertTrue($algo->verify($signingInput, $expectedSignature, $key));
    }

    public function testSignRejectsKeyBoundToDifferentAlg(): void
    {
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(48), 'HS384');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/RFC 8725 §3\.1/');

        $algo->sign('input', $key);
    }

    public function testVerifyRejectsKeyBoundToDifferentAlg(): void
    {
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(48), 'HS384');

        $this->expectException(KeyMismatchException::class);

        $algo->verify('input', 'signature', $key);
    }

    /**
     * The McLean RS→HS confusion attack: an attacker takes an RSA-signed
     * token, rewrites `alg` to "HS256", and signs the new token using the
     * RSA public key bytes as the HMAC secret. A library that picks the
     * algorithm from the header and looks up "the key" by id would then
     * verify the forged token with an HMAC of the public key. With the
     * key/algorithm binding enforced here, that path is unreachable —
     * `Hs256::verify` refuses anything that is not an `HmacKey`.
     */
    public function testVerifyRefusesAsymmetricPublicKey(): void
    {
        $algo = new Hs256();
        $rsaPublicKey = self::buildRsaPublicKey('RS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/McLean confusion/');

        $algo->verify('input', 'signature', $rsaPublicKey);
    }

    public function testSignRefusesAsymmetricPrivateKey(): void
    {
        $algo = new Hs256();
        $rsaPrivateKey = self::buildRsaPrivateKey('RS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/McLean confusion/');

        $algo->sign('input', $rsaPrivateKey);
    }

    public function testSignRefusedWhenKeyOpsDisallowsSign(): void
    {
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', keyOps: ['verify']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/operation "sign"/');

        $algo->sign('input', $key);
    }

    public function testVerifyRefusedWhenKeyOpsDisallowsVerify(): void
    {
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', keyOps: ['sign']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/operation "verify"/');

        $algo->verify('input', 'signature', $key);
    }

    public function testVerifyRefusedWhenUseIsEnc(): void
    {
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', use: KeyUse::Enc);

        $this->expectException(KeyMismatchException::class);

        $algo->verify('input', 'signature', $key);
    }

    private static function buildRsaPublicKey(string $alg): RsaPublicKey
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource);

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        /** @var string $publicPem */
        $publicPem = $details['key'];

        return RsaPublicKey::fromPem($publicPem, $alg);
    }

    private static function buildRsaPrivateKey(string $alg): RsaPrivateKey
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource);

        $privatePem = '';
        openssl_pkey_export($resource, $privatePem);

        return RsaPrivateKey::fromPem($privatePem, $alg);
    }
}
