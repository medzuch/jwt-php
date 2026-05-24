<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;

/**
 * Shared state for {@see OkpPublicKey} and {@see OkpPrivateKey}.
 *
 * OKP ("Octet Key Pair", RFC 8037) keys are not OpenSSL resources — they
 * are raw byte strings consumed directly by libsodium. The base holds the
 * raw public material (32 bytes for Ed25519) so subclasses can hand it
 * straight to `sodium_crypto_sign_*`.
 *
 * Phase 2 supports only `crv: Ed25519` paired with `alg: EdDSA`. Ed448 is
 * not exposed by PHP's libsodium binding; X25519/X448 are key-agreement
 * curves, not signing, and belong in the JWE phase.
 */
abstract class OkpKey extends AsymmetricKey
{
    public const CURVE_ED25519 = 'Ed25519';

    public const ALG_EDDSA = 'EdDSA';

    /**
     * @param non-empty-string $publicKey raw 32-byte Ed25519 public key
     * @param list<string>|null $keyOps
     *
     * @throws InvalidKeyException
     */
    protected function __construct(
        private readonly string $publicKey,
        string $alg,
        ?string $kid = null,
        ?KeyUse $use = null,
        ?array $keyOps = null,
    ) {
        parent::__construct($alg, $kid, $use, $keyOps);

        if ($alg !== self::ALG_EDDSA) {
            throw new InvalidKeyException(sprintf('OkpKey supports alg "%s", got "%s"', self::ALG_EDDSA, $alg));
        }
        if (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidKeyException(sprintf('Ed25519 public key must be %d bytes, got %d', SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, strlen($publicKey)));
        }
    }

    /**
     * @internal consumed by the EdDSA algorithm class
     *
     * @return non-empty-string raw 32-byte Ed25519 public key
     */
    public function publicKeyBytes(): string
    {
        return $this->publicKey;
    }

    public function curve(): string
    {
        return self::CURVE_ED25519;
    }
}
