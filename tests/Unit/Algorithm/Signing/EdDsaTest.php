<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\Signing;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\EdDsa;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\OkpKey;
use Medzuch\Jwt\Key\OkpPrivateKey;
use Medzuch\Jwt\Key\OkpPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(EdDsa::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(Key::class)]
#[UsesClass(KeyUse::class)]
#[UsesClass(OkpKey::class)]
#[UsesClass(OkpPrivateKey::class)]
#[UsesClass(OkpPublicKey::class)]
#[UsesClass(Base64Url::class)]
final class EdDsaTest extends TestCase
{
    /**
     * RFC 8037 §A.1 — Ed25519 keypair.
     */
    private const X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';

    private const D = 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A';

    /** @return array<string, mixed> */
    private static function privJwk(): array
    {
        return ['kty' => 'OKP', 'alg' => 'EdDSA', 'crv' => 'Ed25519', 'x' => self::X, 'd' => self::D];
    }

    /** @return array<string, mixed> */
    private static function pubJwk(): array
    {
        $jwk = self::privJwk();
        unset($jwk['d']);

        return $jwk;
    }

    public function testAlgorithmNameAndFamily(): void
    {
        self::assertSame('EdDSA', (new EdDsa())->name());
        self::assertSame(AlgorithmFamily::EdDsa, (new EdDsa())->family());
    }

    public function testSignAndVerifyRoundTrip(): void
    {
        $priv = OkpPrivateKey::fromJwk(self::privJwk());
        $pub = OkpPublicKey::fromJwk(self::pubJwk());
        $alg = new EdDsa();

        $signature = $alg->sign('signing-input', $priv);

        self::assertSame(64, strlen($signature));
        self::assertTrue($alg->verify('signing-input', $signature, $pub));
    }

    public function testSignatureIsDeterministic(): void
    {
        // Ed25519 is deterministic by construction (RFC 8032 §5.1.6).
        // Two signatures over the same input MUST be equal — this is the
        // property that makes RFC 8037 §A.4 reproducible byte-for-byte.
        $priv = OkpPrivateKey::fromJwk(self::privJwk());
        $alg = new EdDsa();

        $a = $alg->sign('payload', $priv);
        $b = $alg->sign('payload', $priv);

        self::assertSame(bin2hex($a), bin2hex($b));
    }

    public function testVerifyRejectsTamperedPayload(): void
    {
        $priv = OkpPrivateKey::fromJwk(self::privJwk());
        $pub = OkpPublicKey::fromJwk(self::pubJwk());
        $alg = new EdDsa();

        $signature = $alg->sign('input', $priv);

        self::assertFalse($alg->verify('tampered', $signature, $pub));
    }

    public function testVerifyRejectsTamperedSignature(): void
    {
        $priv = OkpPrivateKey::fromJwk(self::privJwk());
        $pub = OkpPublicKey::fromJwk(self::pubJwk());
        $alg = new EdDsa();

        $signature = $alg->sign('input', $priv);
        $signature[10] = chr(ord($signature[10]) ^ 0x01);

        self::assertFalse($alg->verify('input', $signature, $pub));
    }

    public function testVerifyRejectsSignatureOfWrongLength(): void
    {
        $pub = OkpPublicKey::fromJwk(self::pubJwk());

        // Ed25519 signatures are exactly 64 bytes; libsodium throws
        // SodiumException on other lengths, which we surface as `false`.
        self::assertFalse((new EdDsa())->verify('input', str_repeat("\x00", 63), $pub));
    }

    public function testVerifyRejectsEmptySignature(): void
    {
        // The empty-string short-circuit fires before libsodium, which
        // rejects empty-string at the type level (non-empty-string).
        $pub = OkpPublicKey::fromJwk(self::pubJwk());

        self::assertFalse((new EdDsa())->verify('input', '', $pub));
    }

    public function testSignatureFromDifferentKeyIsRejected(): void
    {
        // Same curve, different keypair: signs successfully but verify
        // returns false. This exercises the genuine libsodium verify path
        // (not the wrong-length shortcut).
        $priv = OkpPrivateKey::fromJwk(self::privJwk());
        $alg = new EdDsa();
        $signature = $alg->sign('input', $priv);

        // Build a different Ed25519 keypair from a different seed.
        $otherSeed = str_repeat("\x42", SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $otherKeypair = sodium_crypto_sign_seed_keypair($otherSeed);
        $otherPubBytes = sodium_crypto_sign_publickey($otherKeypair);
        $otherJwk = [
            'kty' => 'OKP', 'alg' => 'EdDSA', 'crv' => 'Ed25519',
            'x' => Base64Url::encode($otherPubBytes),
        ];
        $otherPub = OkpPublicKey::fromJwk($otherJwk);

        self::assertFalse($alg->verify('input', $signature, $otherPub));
    }

    public function testSignRejectsNonOkpPrivateKey(): void
    {
        $hmac = HmacKey::fromBinary(str_repeat("\x01", 32), 'HS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/EdDSA requires OkpPrivateKey/');

        (new EdDsa())->sign('input', $hmac);
    }

    public function testVerifyRejectsNonOkpPublicKey(): void
    {
        $hmac = HmacKey::fromBinary(str_repeat("\x01", 32), 'HS256');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/EdDSA requires OkpPublicKey/');

        (new EdDsa())->verify('input', str_repeat("\x00", 64), $hmac);
    }

    public function testSignRejectsKeyWithoutSignKeyOp(): void
    {
        $priv = OkpPrivateKey::fromJwk(self::privJwk() + ['key_ops' => ['verify']]);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/does not permit operation "sign"/');

        (new EdDsa())->sign('input', $priv);
    }

    public function testVerifyRejectsKeyWithoutVerifyKeyOp(): void
    {
        $pub = OkpPublicKey::fromJwk(self::pubJwk() + ['key_ops' => ['sign']]);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/does not permit operation "verify"/');

        (new EdDsa())->verify('input', str_repeat("\x00", 64), $pub);
    }

}
