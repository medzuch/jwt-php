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
 * EC private key bound to one of ES256, ES384, ES512.
 *
 * Loads PEM-encoded ECPrivateKey ("-----BEGIN EC PRIVATE KEY-----") or
 * PKCS#8 ("-----BEGIN PRIVATE KEY-----"), or a JWK with `kty:"EC"` and
 * `d`. Encrypted PEMs are not supported — pass an already-decrypted key.
 */
final class EcPrivateKey extends EcKey implements PrivateKey
{
    /**
     * Load a private key from PEM.
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

        $key = openssl_pkey_get_private($pem);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new InvalidKeyException(self::opensslError('Failed to load EC private key from PEM'));
        }

        self::assertEc($key);

        return new self($key, $alg, $kid, $use, $keyOps);
    }

    /**
     * Build a private EC key from an RFC 7518 §6.2.2 JWK.
     *
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function fromJwk(array $jwk): self
    {
        $kty = JwkAttributes::requireString($jwk, 'kty');
        if ($kty !== 'EC') {
            throw new InvalidKeyException(sprintf('EcPrivateKey::fromJwk requires kty "EC", got "%s"', $kty));
        }

        $alg = JwkAttributes::requireString($jwk, 'alg');
        $crv = JwkAttributes::requireString($jwk, 'crv');
        $curve = EcCurve::fromJwkName($crv);
        if ($curve->alg !== $alg) {
            throw new InvalidKeyException(sprintf('JWK crv "%s" pairs with alg "%s", got "%s"', $crv, $curve->alg, $alg));
        }

        $x = self::decodeCoordinate($jwk, 'x', $curve);
        $y = self::decodeCoordinate($jwk, 'y', $curve);
        $d = self::decodeCoordinate($jwk, 'd', $curve);

        $pem = self::privatePem($x, $y, $d, $curve);

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
        /** @var array<string, mixed> $ec */
        $ec = $this->details()['ec'];
        $components = [];
        foreach (['x', 'y', 'd'] as $param) {
            $value = $ec[$param] ?? null;
            if (!is_string($value)) {
                // @codeCoverageIgnoreStart
                throw new InvalidKeyException(sprintf('OpenSSL returned EC details missing "%s"', $param));
                // @codeCoverageIgnoreEnd
            }
            $components[$param] = $value;
        }

        $curve = $this->curve();
        $jwk = [
            'kty' => 'EC',
            'alg' => $this->alg(),
            'crv' => $curve->jwkName,
            'x' => Base64Url::encode(self::leftPad($components['x'], $curve->coordSize)),
            'y' => Base64Url::encode(self::leftPad($components['y'], $curve->coordSize)),
            'd' => Base64Url::encode(self::leftPad($components['d'], $curve->coordSize)),
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
    public function toPublicKey(): EcPublicKey
    {
        $public = $this->toJwk();
        unset($public['d']);

        return EcPublicKey::fromJwk($public);
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
     * Build an ECPrivateKey PEM (RFC 5915) wrapping the scalar `d` and the
     * matching public point `(x, y)`.
     *
     * @param non-empty-string $x
     * @param non-empty-string $y
     * @param non-empty-string $d
     */
    private static function privatePem(string $x, string $y, string $d, EcCurve $curve): string
    {
        $version = Asn1::integer("\x01");
        $privateKey = Asn1::octetString($d);
        $parameters = Asn1::contextTagged(0, Asn1::oid($curve->oid));
        $publicKey = Asn1::contextTagged(1, Asn1::bitString("\x04" . $x . $y));

        $body = Asn1::sequence($version . $privateKey . $parameters . $publicKey);

        return Asn1::toPem($body, 'EC PRIVATE KEY');
    }

    /**
     * @throws InvalidKeyException
     */
    private static function leftPad(string $bytes, int $size): string
    {
        if (strlen($bytes) > $size) {
            // @codeCoverageIgnoreStart
            throw new InvalidKeyException(sprintf('EC component (%d bytes) exceeds curve coord size (%d)', strlen($bytes), $size));
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
            throw new InvalidKeyException('PEM is not an EC key (EcPrivateKey rejects RSA/DSA/Ed25519 input)');
        }
        if (!array_key_exists('ec', $details)
            || !is_array($details['ec'])
            || !array_key_exists('d', $details['ec'])
        ) {
            throw new InvalidKeyException('PEM does not include private parameters (use EcPublicKey::fromPem for public keys)');
        }
    }
}
