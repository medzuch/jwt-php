<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\Signing;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\EcdsaSigningAlgorithm;
use Medzuch\Jwt\Algorithm\Signing\Es256;
use Medzuch\Jwt\Algorithm\Signing\Es384;
use Medzuch\Jwt\Algorithm\Signing\Es512;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\EcKey;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\EcCurve;
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

#[CoversClass(EcdsaSigningAlgorithm::class)]
#[CoversClass(Es256::class)]
#[CoversClass(Es384::class)]
#[CoversClass(Es512::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(EcCurve::class)]
#[UsesClass(EcKey::class)]
#[UsesClass(EcPrivateKey::class)]
#[UsesClass(EcPublicKey::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(Key::class)]
#[UsesClass(KeyUse::class)]
#[UsesClass(Rs256::class)]
#[UsesClass(RsaKey::class)]
#[UsesClass(RsaPrivateKey::class)]
#[UsesClass(RsaPublicKey::class)]
final class EcdsaSigningAlgorithmTest extends TestCase
{
    /** @var array<string, array{publicPem: string, privatePem: string}> */
    private static array $pem;

    public static function setUpBeforeClass(): void
    {
        self::$pem = [];
        foreach (['ES256' => 'prime256v1', 'ES384' => 'secp384r1', 'ES512' => 'secp521r1'] as $alg => $curve) {
            $priv = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
            self::assertNotFalse($priv);
            $privatePem = '';
            self::assertTrue(openssl_pkey_export($priv, $privatePem));
            $details = openssl_pkey_get_details($priv);
            self::assertIsArray($details);
            self::$pem[$alg] = ['publicPem' => $details['key'], 'privatePem' => $privatePem];
        }
    }

    /** @return iterable<string, array{string, int}> */
    public static function algAndSigSize(): iterable
    {
        yield 'ES256' => ['ES256', 64];
        yield 'ES384' => ['ES384', 96];
        yield 'ES512' => ['ES512', 132];
    }

    public function testAlgorithmNamesAndFamily(): void
    {
        self::assertSame('ES256', (new Es256())->name());
        self::assertSame('ES384', (new Es384())->name());
        self::assertSame('ES512', (new Es512())->name());
        self::assertSame(AlgorithmFamily::Ecdsa, (new Es256())->family());
    }

    #[DataProvider('algAndSigSize')]
    public function testSignAndVerifyRoundTrip(string $alg, int $sigSize): void
    {
        [$priv, $pub] = $this->keyPair($alg);
        $algorithm = $this->algorithm($alg);

        $signature = $algorithm->sign('signing-input', $priv);
        self::assertSame($sigSize, strlen($signature));
        self::assertTrue($algorithm->verify('signing-input', $signature, $pub));
    }

    #[DataProvider('algAndSigSize')]
    public function testSignatureIsNonDeterministic(string $alg, int $sigSize): void
    {
        // ECDSA picks a random nonce per signature; two signatures over the
        // same input must differ. Both must still verify.
        [$priv, $pub] = $this->keyPair($alg);
        $algorithm = $this->algorithm($alg);

        $a = $algorithm->sign('input', $priv);
        $b = $algorithm->sign('input', $priv);

        self::assertNotSame($a, $b, 'ECDSA signatures must use a fresh nonce per call');
        self::assertTrue($algorithm->verify('input', $a, $pub));
        self::assertTrue($algorithm->verify('input', $b, $pub));
    }

    public function testVerifyRejectsTamperedPayload(): void
    {
        [$priv, $pub] = $this->keyPair('ES256');
        $algorithm = new Es256();
        $signature = $algorithm->sign('input', $priv);

        self::assertFalse($algorithm->verify('tampered', $signature, $pub));
    }

    public function testVerifyRejectsTamperedSignature(): void
    {
        [$priv, $pub] = $this->keyPair('ES256');
        $algorithm = new Es256();
        $signature = $algorithm->sign('input', $priv);

        // Flip a byte in the middle of r.
        $signature[5] = chr(ord($signature[5]) ^ 0x01);

        self::assertFalse($algorithm->verify('input', $signature, $pub));
    }

    public function testVerifyRejectsSignatureOfWrongLength(): void
    {
        [, $pub] = $this->keyPair('ES256');
        $algorithm = new Es256();

        // 65 bytes is one too many for P-256; the algorithm refuses without
        // even reaching the OpenSSL backend.
        self::assertFalse($algorithm->verify('input', str_repeat("\x00", 65), $pub));
    }

    public function testSignRejectsNonEcPrivateKey(): void
    {
        $hmac = HmacKey::fromBinary(str_repeat("\x01", 32), 'HS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/ES256 requires EcPrivateKey/');

        (new Es256())->sign('input', $hmac);
    }

    public function testVerifyRejectsNonEcPublicKey(): void
    {
        $hmac = HmacKey::fromBinary(str_repeat("\x01", 32), 'HS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/ES256 requires EcPublicKey/');

        (new Es256())->verify('input', str_repeat("\x00", 64), $hmac);
    }

    public function testSignRejectsKeyBoundToDifferentAlgorithm(): void
    {
        // Load the same PEM under ES384, then sign with Es256 — the
        // key.assertAlgorithm("ES256") guard fires before any crypto.
        $priv = EcPrivateKey::fromPem(self::$pem['ES384']['privatePem'], 'ES384');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/bound to algorithm "ES384"/');

        (new Es256())->sign('input', $priv);
    }

    public function testVerifyRejectsKeyBoundToDifferentAlgorithm(): void
    {
        $pub = EcPublicKey::fromPem(self::$pem['ES384']['publicPem'], 'ES384');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/bound to algorithm "ES384"/');

        (new Es256())->verify('input', str_repeat("\x00", 64), $pub);
    }

    public function testSignRejectsKeyWithoutSignKeyOp(): void
    {
        $priv = EcPrivateKey::fromPem(self::$pem['ES256']['privatePem'], 'ES256', kid: 'k1', keyOps: ['verify']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/does not permit operation "sign"/');

        (new Es256())->sign('input', $priv);
    }

    public function testVerifyRejectsKeyWithoutVerifyKeyOp(): void
    {
        $pub = EcPublicKey::fromPem(self::$pem['ES256']['publicPem'], 'ES256', kid: 'k1', keyOps: ['sign']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/does not permit operation "verify"/');

        (new Es256())->verify('input', str_repeat("\x00", 64), $pub);
    }

    public function testSignRejectsRsaPrivateKey(): void
    {
        // McLean-style algorithm-confusion: an attacker swapping an RSA
        // private key into an ECDSA flow must hit a type check, not a
        // silent backend error.
        $rsaResource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertNotFalse($rsaResource);
        $rsaPem = '';
        self::assertTrue(openssl_pkey_export($rsaResource, $rsaPem));
        $rsa = RsaPrivateKey::fromPem($rsaPem, 'RS256');

        $this->expectException(KeyMismatchException::class);

        (new Es256())->sign('input', $rsa);
    }

    public function testCrossAlgorithmSignatureFailsVerification(): void
    {
        // A signature produced by ES256 must not verify under ES384 even
        // if we somehow tried to feed it the wrong key class — the
        // type/binding layer already prevents this, but as a final
        // defence the verifier returns false on wrong sig length.
        [$priv, ] = $this->keyPair('ES256');
        $algorithm256 = new Es256();
        $signature = $algorithm256->sign('input', $priv);

        // Build an ES384 public key (different curve) and try to verify
        // the ES256 signature; the length pre-check trips first.
        $pub384 = EcPublicKey::fromPem(self::$pem['ES384']['publicPem'], 'ES384');
        self::assertFalse((new Es384())->verify('input', $signature, $pub384));
    }

    /**
     * @return array{EcPrivateKey, EcPublicKey}
     */
    private function keyPair(string $alg): array
    {
        $priv = EcPrivateKey::fromPem(self::$pem[$alg]['privatePem'], $alg);
        $pub = EcPublicKey::fromPem(self::$pem[$alg]['publicPem'], $alg);

        return [$priv, $pub];
    }

    private function algorithm(string $alg): EcdsaSigningAlgorithm
    {
        return match ($alg) {
            'ES256' => new Es256(),
            'ES384' => new Es384(),
            'ES512' => new Es512(),
            default => throw new \LogicException('unknown alg ' . $alg),
        };
    }
}
