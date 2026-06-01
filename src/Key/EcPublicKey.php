<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\EcCurve;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Primitives\Base64Url;
use OpenSSLAsymmetricKey;
use Throwable;

/**
 * EC public key bound to one of ES256, ES384, ES512.
 *
 * Loads PEM-encoded SubjectPublicKeyInfo (the "PUBLIC KEY" envelope) or
 * a JWK with `kty:"EC"`. The point is round-tripped through OpenSSL's
 * EC_POINT_oct2point on load, which gives us point-on-curve validation
 * for free: off-curve `(x, y)` pairs are rejected with `InvalidKeyException`.
 */
final class EcPublicKey extends EcKey implements PublicKey
{
    /**
     * Load a public key from PEM ("-----BEGIN PUBLIC KEY-----").
     *
     * @param list<string>|null $keyOps
     *
     * @throws InvalidKeyException
     */
    public static function fromPem(
        string $pem,
        string $alg,
        ?string $kid = null,
        ?KeyUse $use = null,
        ?array $keyOps = null,
    ): self {
        while (openssl_error_string() !== false) {
        }

        $key = openssl_pkey_get_public($pem);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new InvalidKeyException(self::opensslError('Failed to load EC public key from PEM'));
        }

        self::assertEc($key);

        return new self($key, $alg, $kid, $use, $keyOps);
    }

    /**
     * Build a public EC key from an RFC 7518 §6.2 JWK (`kty:"EC"`, no `d`).
     *
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function fromJwk(array $jwk): self
    {
        $kty = JwkAttributes::requireString($jwk, 'kty');
        if ($kty !== 'EC') {
            throw new InvalidKeyException(sprintf('EcPublicKey::fromJwk requires kty "EC", got "%s"', $kty));
        }
        if (array_key_exists('d', $jwk)) {
            throw new InvalidKeyException('JWK contains "d"; load via EcPrivateKey::fromJwk instead');
        }

        $alg = JwkAttributes::requireString($jwk, 'alg');
        $crv = JwkAttributes::requireString($jwk, 'crv');
        $curve = EcCurve::fromJwkName($crv);
        // ECDH-ES keys are not pinned to a curve by their alg; only the ECDSA
        // signing algorithms require the crv↔alg pairing (RFC 7518 §3.4).
        if (EcCurve::bindsToFixedCurve($alg) && $curve->alg !== $alg) {
            throw new InvalidKeyException(sprintf('JWK crv "%s" pairs with alg "%s", got "%s"', $crv, $curve->alg, $alg));
        }

        $x = self::decodeCoordinate($jwk, 'x', $curve);
        $y = self::decodeCoordinate($jwk, 'y', $curve);
        $pem = self::publicPem($x, $y, $curve);

        return self::fromPem(
            $pem,
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
        $ec = $this->details()['ec'];
        /** @var array<string, mixed> $ec */
        if (!isset($ec['x']) || !is_string($ec['x']) || !isset($ec['y']) || !is_string($ec['y'])) {
            // @codeCoverageIgnoreStart
            throw new InvalidKeyException('OpenSSL returned EC details missing "x" or "y"');
            // @codeCoverageIgnoreEnd
        }

        $curve = $this->curve();
        $jwk = [
            'kty' => 'EC',
            'alg' => $this->alg(),
            'crv' => $curve->jwkName,
            'x' => Base64Url::encode(self::leftPad($ec['x'], $curve->coordSize)),
            'y' => Base64Url::encode(self::leftPad($ec['y'], $curve->coordSize)),
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
     * @return non-empty-string
     *
     * @throws InvalidKeyException
     */
    private static function decodeCoordinate(array $jwk, string $param, EcCurve $curve): string
    {
        $encoded = JwkAttributes::requireString($jwk, $param);

        try {
            $bytes = Base64Url::decode($encoded);
        } catch (Throwable $e) {
            throw new InvalidKeyException(sprintf('JWK "%s" is not valid base64url', $param), 0, $e);
        }

        if (strlen($bytes) !== $curve->coordSize) {
            throw new InvalidKeyException(sprintf('JWK "%s" must be %d bytes for %s, got %d', $param, $curve->coordSize, $curve->jwkName, strlen($bytes)));
        }

        /** @var non-empty-string $bytes */
        return $bytes;
    }

    /**
     * Build a SubjectPublicKeyInfo PEM (RFC 5480) for the (x, y) point.
     *
     * @param non-empty-string $x
     * @param non-empty-string $y
     */
    private static function publicPem(string $x, string $y, EcCurve $curve): string
    {
        $algId = Asn1::sequence(
            Asn1::oid('1.2.840.10045.2.1') . Asn1::oid($curve->oid),
        );
        $point = EcCurve::UNCOMPRESSED_POINT . $x . $y;
        $spki = Asn1::sequence($algId . Asn1::bitString($point));

        return Asn1::toPem($spki, 'PUBLIC KEY');
    }

    /**
     * @throws InvalidKeyException
     */
    private static function leftPad(string $bytes, int $size): string
    {
        if (strlen($bytes) > $size) {
            // @codeCoverageIgnoreStart
            throw new InvalidKeyException(sprintf('EC coordinate (%d bytes) exceeds curve coord size (%d)', strlen($bytes), $size));
            // @codeCoverageIgnoreEnd
        }

        return str_repeat("\x00", $size - strlen($bytes)) . $bytes;
    }

    /**
     * @throws InvalidKeyException
     */
    private static function assertEc(OpenSSLAsymmetricKey $key): void
    {
        $details = openssl_pkey_get_details($key);
        if (!is_array($details)) {
            // @codeCoverageIgnoreStart
            throw new InvalidKeyException('OpenSSL could not read key details');
            // @codeCoverageIgnoreEnd
        }
        $type = $details['type'] ?? null;
        if ($type !== OPENSSL_KEYTYPE_EC) {
            throw new InvalidKeyException('PEM is not an EC key (EcPublicKey rejects RSA/DSA/Ed25519 input)');
        }
    }
}
