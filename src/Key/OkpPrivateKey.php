<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Primitives\Base64Url;
use Throwable;

/**
 * Ed25519 private key, RFC 8037 OKP `kty:"OKP"` with `crv:"Ed25519"` and `d`.
 *
 * The JWK `d` parameter is the 32-byte Ed25519 *seed*. libsodium derives
 * the 64-byte secret-key material (seed concatenated with the public key)
 * via {@see sodium_crypto_sign_seed_keypair()}; we cache the result so
 * sign operations don't repeat the derivation.
 *
 * The matching public point is also cross-checked against the JWK `x`
 * field: if they disagree, the JWK is internally inconsistent and we
 * refuse it. This catches accidental swaps and (cheap) integrity bugs.
 */
final class OkpPrivateKey extends OkpKey implements PrivateKey
{
    /**
     * @param non-empty-string $secretKey raw 64-byte libsodium secret key
     * @param non-empty-string $publicKey raw 32-byte Ed25519 public key
     * @param non-empty-string $seed      raw 32-byte Ed25519 seed (JWK `d`)
     * @param list<string>|null $keyOps
     *
     * @throws InvalidKeyException
     */
    private function __construct(
        private readonly string $secretKey,
        string $publicKey,
        private readonly string $seed,
        string $alg,
        ?string $kid = null,
        ?KeyUse $use = null,
        ?array $keyOps = null,
    ) {
        parent::__construct($publicKey, $alg, $kid, $use, $keyOps);
    }

    /**
     * Build a private OKP key from an RFC 8037 §2 JWK.
     *
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function fromJwk(array $jwk): self
    {
        $kty = JwkAttributes::requireString($jwk, 'kty');
        if ($kty !== 'OKP') {
            throw new InvalidKeyException(sprintf('OkpPrivateKey::fromJwk requires kty "OKP", got "%s"', $kty));
        }
        if (!array_key_exists('d', $jwk)) {
            throw new InvalidKeyException('JWK does not contain "d"; load via OkpPublicKey::fromJwk instead');
        }

        $alg = JwkAttributes::requireString($jwk, 'alg');
        $crv = JwkAttributes::requireString($jwk, 'crv');
        if ($crv !== self::CURVE_ED25519) {
            throw new InvalidKeyException(sprintf('OkpPrivateKey supports crv "%s", got "%s"', self::CURVE_ED25519, $crv));
        }

        $x = self::decodeCoordinate($jwk, 'x', SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
        $d = self::decodeCoordinate($jwk, 'd', SODIUM_CRYPTO_SIGN_SEEDBYTES);

        $keypair = sodium_crypto_sign_seed_keypair($d);
        $secretKey = sodium_crypto_sign_secretkey($keypair);
        $derivedPublic = sodium_crypto_sign_publickey($keypair);

        if (!hash_equals($derivedPublic, $x)) {
            throw new InvalidKeyException('JWK "x" does not match the public key derived from "d" (inconsistent JWK)');
        }

        return new self(
            $secretKey,
            $derivedPublic,
            $d,
            $alg,
            JwkAttributes::optionalString($jwk, 'kid'),
            JwkAttributes::optionalKeyUse($jwk),
            JwkAttributes::optionalKeyOps($jwk),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toJwk(): array
    {
        $jwk = [
            'kty' => 'OKP',
            'alg' => $this->alg(),
            'crv' => self::CURVE_ED25519,
            'x' => Base64Url::encode($this->publicKeyBytes()),
            'd' => Base64Url::encode($this->seed),
        ];

        if ($this->kid() !== null) {
            $jwk['kid'] = $this->kid();
        }
        if ($this->use() !== null) {
            $jwk['use'] = $this->use()->value;
        }
        if ($this->keyOps() !== null) {
            $jwk['key_ops'] = $this->keyOps();
        }

        return $jwk;
    }

    /**
     * Public counterpart of this private key (drops `d`).
     *
     * @throws InvalidKeyException
     */
    public function toPublicKey(): OkpPublicKey
    {
        $public = $this->toJwk();
        unset($public['d']);

        return OkpPublicKey::fromJwk($public);
    }

    /**
     * @internal consumed by {@see \Medzuch\Jwt\Algorithm\Signing\EdDsa::sign()}.
     *
     * @return non-empty-string raw 64-byte libsodium secret key
     */
    public function secretKeyBytes(): string
    {
        return $this->secretKey;
    }

    /**
     * @param array<string, mixed> $jwk
     * @param positive-int $expectedBytes
     *
     * @return non-empty-string
     *
     * @throws InvalidKeyException
     */
    private static function decodeCoordinate(array $jwk, string $param, int $expectedBytes): string
    {
        $encoded = JwkAttributes::requireString($jwk, $param);

        try {
            $bytes = Base64Url::decode($encoded);
        } catch (Throwable $e) {
            throw new InvalidKeyException(sprintf('JWK "%s" is not valid base64url', $param), 0, $e);
        }

        if (strlen($bytes) !== $expectedBytes) {
            throw new InvalidKeyException(sprintf('JWK "%s" must be %d bytes for Ed25519, got %d', $param, $expectedBytes, strlen($bytes)));
        }

        return $bytes;
    }
}
