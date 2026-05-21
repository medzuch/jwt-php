<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\Signing;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Algorithm\Signing\Rs384;
use Medzuch\Jwt\Algorithm\Signing\Rs512;
use Medzuch\Jwt\Algorithm\Signing\RsaSigningAlgorithm;
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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function random_bytes;
use function str_repeat;
use function strlen;

use const OPENSSL_KEYTYPE_RSA;

#[CoversClass(RsaSigningAlgorithm::class)]
#[CoversClass(Rs256::class)]
#[CoversClass(Rs384::class)]
#[CoversClass(Rs512::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(Key::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
#[UsesClass(RsaKey::class)]
#[UsesClass(RsaPublicKey::class)]
#[UsesClass(RsaPrivateKey::class)]
#[UsesClass(Asn1::class)]
final class RsaSigningAlgorithmTest extends TestCase
{
    /** @var array{public: string, private: string} */
    private static array $pem;

    public static function setUpBeforeClass(): void
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource, 'openssl_pkey_new failed');

        $privatePem = '';
        openssl_pkey_export($resource, $privatePem);

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        /** @var string $publicPem */
        $publicPem = $details['key'];

        self::$pem = ['public' => $publicPem, 'private' => $privatePem];
    }

    public function testRs256Identity(): void
    {
        $algo = new Rs256();

        self::assertSame('RS256', $algo->name());
        self::assertSame(AlgorithmFamily::Rsa, $algo->family());
    }

    public function testRs384Identity(): void
    {
        $algo = new Rs384();

        self::assertSame('RS384', $algo->name());
        self::assertSame(AlgorithmFamily::Rsa, $algo->family());
    }

    public function testRs512Identity(): void
    {
        $algo = new Rs512();

        self::assertSame('RS512', $algo->name());
        self::assertSame(AlgorithmFamily::Rsa, $algo->family());
    }

    #[DataProvider('algoProvider')]
    public function testRoundTripWithFreshKey(RsaSigningAlgorithm $algo, string $alg): void
    {
        $private = RsaPrivateKey::fromPem(self::$pem['private'], $alg);
        $public = RsaPublicKey::fromPem(self::$pem['public'], $alg);

        $input = 'jws.signing.input';
        $signature = $algo->sign($input, $private);

        self::assertTrue($algo->verify($input, $signature, $public));
    }

    /** @return iterable<string, array{RsaSigningAlgorithm, string}> */
    public static function algoProvider(): iterable
    {
        yield 'RS256' => [new Rs256(), 'RS256'];
        yield 'RS384' => [new Rs384(), 'RS384'];
        yield 'RS512' => [new Rs512(), 'RS512'];
    }

    public function testVerifyRejectsTamperedInput(): void
    {
        $algo = new Rs256();
        $private = RsaPrivateKey::fromPem(self::$pem['private'], 'RS256');
        $public = RsaPublicKey::fromPem(self::$pem['public'], 'RS256');

        $signature = $algo->sign('original', $private);

        self::assertFalse($algo->verify('tampered', $signature, $public));
    }

    public function testVerifyRejectsTamperedSignature(): void
    {
        $algo = new Rs256();
        $private = RsaPrivateKey::fromPem(self::$pem['private'], 'RS256');
        $public = RsaPublicKey::fromPem(self::$pem['public'], 'RS256');

        $signature = $algo->sign('input', $private);
        $tampered = $signature ^ str_repeat("\x01", strlen($signature));

        self::assertFalse($algo->verify('input', $tampered, $public));
    }

    public function testSignRejectsKeyBoundToDifferentAlg(): void
    {
        $algo = new Rs256();
        $private = RsaPrivateKey::fromPem(self::$pem['private'], 'RS384');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/RFC 8725 §3\.1/');

        $algo->sign('input', $private);
    }

    public function testVerifyRejectsKeyBoundToDifferentAlg(): void
    {
        $algo = new Rs256();
        $public = RsaPublicKey::fromPem(self::$pem['public'], 'RS384');

        $this->expectException(KeyMismatchException::class);

        $algo->verify('input', 'signature', $public);
    }

    /**
     * The reverse McLean direction: an HMAC secret used to verify what
     * the header claims is an RSA-signed token. `Rs256::verify` rejects
     * the symmetric key at the type/instance check before the alg
     * binding is even consulted.
     */
    public function testVerifyRefusesSymmetricKey(): void
    {
        $algo = new Rs256();
        $hmac = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/requires RsaPublicKey/');

        $algo->verify('input', 'signature', $hmac);
    }

    public function testSignRefusesSymmetricKey(): void
    {
        $algo = new Rs256();
        $hmac = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/requires RsaPrivateKey/');

        $algo->sign('input', $hmac);
    }

    public function testSignRefusedWhenKeyOpsDisallowsSign(): void
    {
        $algo = new Rs256();
        $private = RsaPrivateKey::fromPem(self::$pem['private'], 'RS256', keyOps: ['verify']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/operation "sign"/');

        $algo->sign('input', $private);
    }

    public function testVerifyRefusedWhenKeyOpsDisallowsVerify(): void
    {
        $algo = new Rs256();
        $public = RsaPublicKey::fromPem(self::$pem['public'], 'RS256', keyOps: ['sign']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/operation "verify"/');

        $algo->verify('input', 'signature', $public);
    }

    public function testVerifyRefusedWhenUseIsEnc(): void
    {
        $algo = new Rs256();
        $public = RsaPublicKey::fromPem(self::$pem['public'], 'RS256', use: KeyUse::Enc);

        $this->expectException(KeyMismatchException::class);

        $algo->verify('input', 'signature', $public);
    }

    public function testSignatureIsExpectedSizeFor2048BitKey(): void
    {
        $algo = new Rs256();
        $private = RsaPrivateKey::fromPem(self::$pem['private'], 'RS256');

        $signature = $algo->sign('payload', $private);

        // RSASSA-PKCS1-v1_5 signature length equals the modulus length;
        // for a 2048-bit key that's 256 bytes.
        self::assertSame(256, strlen($signature));
    }
}
