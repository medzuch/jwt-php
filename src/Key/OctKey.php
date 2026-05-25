<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Primitives\Base64Url;
use Throwable;

/**
 * Symmetric (`kty:"oct"`) key for JWE — the encryption-side counterpart to
 * {@see HmacKey}, which serves JWS signing. Both are `oct` keys; the
 * algorithm binding is what separates them (`HS*` for HMAC signatures, a JWE
 * content-encryption `enc` value here).
 *
 * For `dir` (direct encryption) the key bytes *are* the Content Encryption
 * Key, so the byte length must match the bound algorithm exactly (RFC 7518
 * §5): 16/24/32 bytes for A128/192/256GCM, and 32/48/64 bytes for
 * A128CBC-HS256 / A192CBC-HS384 / A256CBC-HS512 (the CBC-HS family carries a
 * MAC half, doubling the key, RFC 7518 §5.2.2.1). As with {@see HmacKey},
 * there is no password-derived constructor (RFC 8725 §3.5).
 *
 * The AES key-wrapping (`A*KW`) bindings are added in a later PR; they share
 * this class with their own required lengths.
 */
final class OctKey extends SymmetricKey
{
    /** Exact key length in bytes per bound algorithm (RFC 7518 §5). */
    private const EXACT_BYTES = [
        'A128GCM' => 16,
        'A192GCM' => 24,
        'A256GCM' => 32,
        'A128CBC-HS256' => 32,
        'A192CBC-HS384' => 48,
        'A256CBC-HS512' => 64,
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

        if (!array_key_exists($alg, self::EXACT_BYTES)) {
            throw new InvalidKeyException(sprintf('OctKey supports %s, got "%s"', implode('/', array_keys(self::EXACT_BYTES)), $alg));
        }

        $expected = self::EXACT_BYTES[$alg];
        if (strlen($bytes) !== $expected) {
            throw new InvalidKeyException(sprintf('Symmetric key for %s must be exactly %d bytes (RFC 7518 §5); got %d', $alg, $expected, strlen($bytes)));
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
     * Parse an RFC 7517 JWK with `kty:"oct"` bound to a JWE algorithm.
     *
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function fromJwk(array $jwk): self
    {
        $kty = JwkAttributes::requireString($jwk, 'kty');
        if ($kty !== 'oct') {
            throw new InvalidKeyException(sprintf('OctKey::fromJwk requires kty "oct", got "%s"', $kty));
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
     * Raw key bytes for the content-encryption / key-wrapping primitive.
     *
     * @return non-empty-string
     *
     * @internal consumed by the JWE key-management algorithm classes only
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
