<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Primitives\Base64Url;
use Throwable;

/**
 * HMAC secret bound to one of HS256, HS384, HS512.
 *
 * The minimum byte length is enforced per RFC 8725 §3.5 — the secret
 * must be at least as long as the algorithm's hash output (32 / 48 / 64
 * bytes for HS256 / HS384 / HS512). This is the mitigation for T3
 * (weak symmetric keys); there is intentionally no password-derived
 * constructor.
 */
final class HmacKey extends SymmetricKey
{
    /** Minimum secret bytes per algorithm, RFC 8725 §3.5. */
    private const MIN_BYTES = [
        'HS256' => 32,
        'HS384' => 48,
        'HS512' => 64,
    ];

    /** @var non-empty-string */
    private readonly string $bytes;

    /**
     * @param list<string>|null $keyOps
     *
     * @throws InvalidKeyException
     */
    private function __construct(
        string $bytes,
        string $alg,
        ?string $kid = null,
        ?KeyUse $use = null,
        ?array $keyOps = null,
    ) {
        parent::__construct($alg, $kid, $use, $keyOps);

        if (!array_key_exists($alg, self::MIN_BYTES)) {
            throw new InvalidKeyException(sprintf('HmacKey supports HS256/HS384/HS512, got "%s"', $alg));
        }

        $min = self::MIN_BYTES[$alg];
        if (strlen($bytes) < $min) {
            throw new InvalidKeyException(sprintf('HMAC secret for %s must be at least %d bytes (RFC 8725 §3.5); got %d', $alg, $min, strlen($bytes)));
        }

        $this->bytes = $bytes;
    }

    /**
     * @param list<string>|null $keyOps
     *
     * @throws InvalidKeyException
     */
    public static function fromBinary(
        string $bytes,
        string $alg,
        ?string $kid = null,
        ?KeyUse $use = null,
        ?array $keyOps = null,
    ): self {
        return new self($bytes, $alg, $kid, $use, $keyOps);
    }

    /**
     * Parse an RFC 7517 JWK with `kty:"oct"`.
     *
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function fromJwk(array $jwk): self
    {
        $kty = JwkAttributes::requireString($jwk, 'kty');
        if ($kty !== 'oct') {
            throw new InvalidKeyException(sprintf('HmacKey::fromJwk requires kty "oct", got "%s"', $kty));
        }

        $alg = JwkAttributes::requireString($jwk, 'alg');
        $kRaw = JwkAttributes::requireString($jwk, 'k');

        try {
            $bytes = Base64Url::decode($kRaw);
        } catch (Throwable $e) {
            throw new InvalidKeyException('JWK "k" is not valid base64url', 0, $e);
        }

        if ($bytes === '') {
            throw new InvalidKeyException('JWK "k" decoded to an empty string');
        }

        return new self(
            $bytes,
            $alg,
            JwkAttributes::optionalString($jwk, 'kid'),
            JwkAttributes::optionalKeyUse($jwk),
            JwkAttributes::optionalKeyOps($jwk),
        );
    }

    /**
     * Constant-time access to the raw bytes for the HMAC primitive.
     *
     * @return non-empty-string
     *
     * @internal consumed by the HMAC algorithm classes only
     */
    public function bytes(): string
    {
        return $this->bytes;
    }

    /**
     * @return array<string, mixed>
     */
    public function toJwk(): array
    {
        $jwk = [
            'kty' => 'oct',
            'alg' => $this->alg(),
            'k' => Base64Url::encode($this->bytes),
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
}
