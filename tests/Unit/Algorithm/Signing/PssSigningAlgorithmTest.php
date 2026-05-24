<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\Signing;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Internal\Pss;
use Medzuch\Jwt\Algorithm\Signing\Ps256;
use Medzuch\Jwt\Algorithm\Signing\Ps384;
use Medzuch\Jwt\Algorithm\Signing\Ps512;
use Medzuch\Jwt\Algorithm\Signing\PssSigningAlgorithm;
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

#[CoversClass(PssSigningAlgorithm::class)]
#[CoversClass(Ps256::class)]
#[CoversClass(Ps384::class)]
#[CoversClass(Ps512::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(Key::class)]
#[UsesClass(KeyUse::class)]
#[UsesClass(Pss::class)]
#[UsesClass(RsaKey::class)]
#[UsesClass(RsaPrivateKey::class)]
#[UsesClass(RsaPublicKey::class)]
final class PssSigningAlgorithmTest extends TestCase
{
    /** @var array{public: string, private: string} */
    private static array $pem;

    public static function setUpBeforeClass(): void
    {
        $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertNotFalse($resource);
        $privatePem = '';
        self::assertTrue(openssl_pkey_export($resource, $privatePem));
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        self::$pem = ['public' => $details['key'], 'private' => $privatePem];
    }

    /** @return iterable<string, array{PssSigningAlgorithm, string}> */
    public static function algorithms(): iterable
    {
        yield 'PS256' => [new Ps256(), 'PS256'];
        yield 'PS384' => [new Ps384(), 'PS384'];
        yield 'PS512' => [new Ps512(), 'PS512'];
    }

    #[DataProvider('algorithms')]
    public function testAlgorithmName(PssSigningAlgorithm $alg, string $name): void
    {
        self::assertSame($name, $alg->name());
        self::assertSame(AlgorithmFamily::Rsa, $alg->family());
    }

    #[DataProvider('algorithms')]
    public function testSignAndVerifyRoundTrip(PssSigningAlgorithm $alg, string $name): void
    {
        $priv = RsaPrivateKey::fromPem(self::$pem['private'], $name);
        $pub = RsaPublicKey::fromPem(self::$pem['public'], $name);

        $signature = $alg->sign('signing-input', $priv);

        // For 2048-bit RSA, signature is exactly 256 bytes.
        self::assertSame(256, strlen($signature));
        self::assertTrue($alg->verify('signing-input', $signature, $pub));
    }

    #[DataProvider('algorithms')]
    public function testSignatureIsNonDeterministic(PssSigningAlgorithm $alg, string $name): void
    {
        // PSS randomises the salt per signature (RFC 8017 §9.1.1 step 3).
        $priv = RsaPrivateKey::fromPem(self::$pem['private'], $name);
        $pub = RsaPublicKey::fromPem(self::$pem['public'], $name);

        $a = $alg->sign('input', $priv);
        $b = $alg->sign('input', $priv);

        self::assertNotSame($a, $b);
        self::assertTrue($alg->verify('input', $a, $pub));
        self::assertTrue($alg->verify('input', $b, $pub));
    }

    /**
     * Critical interop check: a signature we produce must verify under
     * OpenSSL's PSS verification path, and vice versa.
     */
    #[DataProvider('algorithms')]
    public function testOpensslCliCanVerifyOurSignature(PssSigningAlgorithm $alg, string $name): void
    {
        $priv = RsaPrivateKey::fromPem(self::$pem['private'], $name);
        $signature = $alg->sign('interop-message', $priv);

        $hashName = ['PS256' => 'sha256', 'PS384' => 'sha384', 'PS512' => 'sha512'][$name];
        $tmpDir = sys_get_temp_dir();
        $msgFile = tempnam($tmpDir, 'pss-msg-');
        $sigFile = tempnam($tmpDir, 'pss-sig-');
        $pubFile = tempnam($tmpDir, 'pss-pub-');
        self::assertNotFalse($msgFile);
        self::assertNotFalse($sigFile);
        self::assertNotFalse($pubFile);

        try {
            file_put_contents($msgFile, 'interop-message');
            file_put_contents($sigFile, $signature);
            file_put_contents($pubFile, self::$pem['public']);

            $cmd = sprintf(
                'openssl dgst -%s -verify %s -signature %s -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest %s 2>&1',
                escapeshellarg($hashName),
                escapeshellarg($pubFile),
                escapeshellarg($sigFile),
                escapeshellarg($msgFile),
            );
            $output = shell_exec($cmd);

            self::assertNotNull($output);
            self::assertNotFalse($output);
            self::assertStringContainsString('Verified OK', $output, sprintf('openssl rejected our %s signature: %s', $name, $output));
        } finally {
            @unlink($msgFile);
            @unlink($sigFile);
            @unlink($pubFile);
        }
    }

    #[DataProvider('algorithms')]
    public function testWeCanVerifyOpensslCliSignature(PssSigningAlgorithm $alg, string $name): void
    {
        $hashName = ['PS256' => 'sha256', 'PS384' => 'sha384', 'PS512' => 'sha512'][$name];
        $tmpDir = sys_get_temp_dir();
        $msgFile = tempnam($tmpDir, 'pss-msg-');
        $sigFile = tempnam($tmpDir, 'pss-sig-');
        $privFile = tempnam($tmpDir, 'pss-priv-');
        self::assertNotFalse($msgFile);
        self::assertNotFalse($sigFile);
        self::assertNotFalse($privFile);

        try {
            file_put_contents($msgFile, 'reverse-interop');
            file_put_contents($privFile, self::$pem['private']);

            shell_exec(sprintf(
                'openssl dgst -%s -sign %s -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -out %s %s 2>&1',
                escapeshellarg($hashName),
                escapeshellarg($privFile),
                escapeshellarg($sigFile),
                escapeshellarg($msgFile),
            ));
            $signature = file_get_contents($sigFile);
            self::assertNotFalse($signature);
            self::assertNotEmpty($signature);

            $pub = RsaPublicKey::fromPem(self::$pem['public'], $name);
            self::assertTrue($alg->verify('reverse-interop', $signature, $pub));
        } finally {
            @unlink($msgFile);
            @unlink($sigFile);
            @unlink($privFile);
        }
    }

    public function testVerifyRejectsTamperedPayload(): void
    {
        $priv = RsaPrivateKey::fromPem(self::$pem['private'], 'PS256');
        $pub = RsaPublicKey::fromPem(self::$pem['public'], 'PS256');
        $alg = new Ps256();

        $signature = $alg->sign('input', $priv);

        self::assertFalse($alg->verify('tampered', $signature, $pub));
    }

    public function testVerifyRejectsTamperedSignature(): void
    {
        $priv = RsaPrivateKey::fromPem(self::$pem['private'], 'PS256');
        $pub = RsaPublicKey::fromPem(self::$pem['public'], 'PS256');
        $alg = new Ps256();

        $signature = $alg->sign('input', $priv);
        $signature[5] = chr(ord($signature[5]) ^ 0x01);

        self::assertFalse($alg->verify('input', $signature, $pub));
    }

    public function testVerifyRejectsSignatureOfWrongLength(): void
    {
        $pub = RsaPublicKey::fromPem(self::$pem['public'], 'PS256');

        // For 2048-bit RSA, valid signatures are exactly 256 bytes.
        self::assertFalse((new Ps256())->verify('input', str_repeat("\x00", 255), $pub));
        self::assertFalse((new Ps256())->verify('input', str_repeat("\x00", 257), $pub));
    }

    public function testVerifyRejectsAllZeroSignature(): void
    {
        // A 256-byte all-zero signature decrypts to all-zero EM, whose
        // trailer byte is 0x00 not 0xbc — must be rejected.
        $pub = RsaPublicKey::fromPem(self::$pem['public'], 'PS256');

        self::assertFalse((new Ps256())->verify('input', str_repeat("\x00", 256), $pub));
    }

    public function testSignRejectsHmacKey(): void
    {
        $hmac = HmacKey::fromBinary(str_repeat("\x01", 32), 'HS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/PS256 requires RsaPrivateKey/');

        (new Ps256())->sign('input', $hmac);
    }

    public function testVerifyRejectsHmacKey(): void
    {
        $hmac = HmacKey::fromBinary(str_repeat("\x01", 32), 'HS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/PS256 requires RsaPublicKey/');

        (new Ps256())->verify('input', str_repeat("\x00", 256), $hmac);
    }

    public function testSignRejectsKeyBoundToDifferentAlgorithm(): void
    {
        // Same RSA key, but bound at construction to RS256. PS256 must
        // refuse it — algorithm confusion (RFC 8725 §3.1).
        $priv = RsaPrivateKey::fromPem(self::$pem['private'], 'RS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/bound to algorithm "RS256"/');

        (new Ps256())->sign('input', $priv);
    }

    public function testVerifyRejectsKeyBoundToDifferentAlgorithm(): void
    {
        $pub = RsaPublicKey::fromPem(self::$pem['public'], 'RS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/bound to algorithm "RS256"/');

        (new Ps256())->verify('input', str_repeat("\x00", 256), $pub);
    }

    public function testSignRejectsKeyWithoutSignKeyOp(): void
    {
        $priv = RsaPrivateKey::fromPem(self::$pem['private'], 'PS256', kid: 'k', keyOps: ['verify']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/does not permit operation "sign"/');

        (new Ps256())->sign('input', $priv);
    }

    public function testVerifyRejectsKeyWithoutVerifyKeyOp(): void
    {
        $pub = RsaPublicKey::fromPem(self::$pem['public'], 'PS256', kid: 'k', keyOps: ['sign']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/does not permit operation "verify"/');

        (new Ps256())->verify('input', str_repeat("\x00", 256), $pub);
    }
}
