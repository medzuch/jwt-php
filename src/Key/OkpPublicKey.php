<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Primitives\Base64Url;
use Throwable;

/**
 * Ed25519 public key, RFC 8037 OKP `kty:"OKP"` with `crv:"Ed25519"`.
 *
 * No PEM constructor in this phase — RFC 8037 defines only the JWK
 * encoding for OKP, and PHP's libsodium does not parse PEM.
 */
final class OkpPublicKey extends OkpKey implements PublicKey
{
    /**
     * Build a public OKP key from an RFC 8037 §2 JWK
     * (`kty:"OKP"`, `crv:"Ed25519"`, no `d`).
     *
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function fromJwk(array $jwk): self
    {
        $kty = JwkAttributes::requireString($jwk, 'kty');
        if ($kty !== 'OKP') {
            throw new InvalidKeyException(sprintf('OkpPublicKey::fromJwk requires kty "OKP", got "%s"', $kty));
        }
        if (array_key_exists('d', $jwk)) {
            throw new InvalidKeyException('JWK contains "d"; load via OkpPrivateKey::fromJwk instead');
        }

        $alg = JwkAttributes::requireString($jwk, 'alg');
        $crv = JwkAttributes::requireString($jwk, 'crv');
        if ($crv !== self::CURVE_ED25519) {
            throw new InvalidKeyException(sprintf('OkpPublicKey supports crv "%s", got "%s"', self::CURVE_ED25519, $crv));
        }

        $public = self::decodeCoordinate($jwk, 'x');

        return new self(
            $public,
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
     * @param array<string, mixed> $jwk
     *
     * @return non-empty-string raw 32-byte coordinate
     *
     * @throws InvalidKeyException
     */
    private static function decodeCoordinate(array $jwk, string $param): string
    {
        $encoded = JwkAttributes::requireString($jwk, $param);

        try {
            $bytes = Base64Url::decode($encoded);
        } catch (Throwable $e) {
            throw new InvalidKeyException(sprintf('JWK "%s" is not valid base64url', $param), 0, $e);
        }

        if (strlen($bytes) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidKeyException(sprintf('JWK "%s" must be %d bytes for Ed25519, got %d', $param, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, strlen($bytes)));
        }

        return $bytes;
    }
}
