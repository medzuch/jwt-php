<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Primitives\Base64Url;
use OpenSSLAsymmetricKey;

/**
 * RSA public key bound to one of RS256, RS384, RS512.
 *
 * Refuses to load a private PEM (defence-in-depth: the JWK and PEM
 * importers both verify the key is "public" before constructing).
 */
final class RsaPublicKey extends RsaKey implements PublicKey
{
    /**
     * Load a public key from PEM ("-----BEGIN PUBLIC KEY-----" or
     * "-----BEGIN RSA PUBLIC KEY-----").
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
        // Drain any preceding OpenSSL error queue so our error_string read
        // below sees only failures from this call.
        while (openssl_error_string() !== false) {
        }

        $key = openssl_pkey_get_public($pem);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new InvalidKeyException(self::opensslError('Failed to load RSA public key from PEM'));
        }

        self::assertRsa($key);

        return new self($key, $alg, $kid, $use, $keyOps);
    }

    /**
     * Build a public RSA key from an RFC 7517 JWK (`kty:"RSA"`, no `d`).
     *
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function fromJwk(array $jwk): self
    {
        $kty = JwkAttributes::requireString($jwk, 'kty');
        if ($kty !== 'RSA') {
            throw new InvalidKeyException(sprintf('RsaPublicKey::fromJwk requires kty "RSA", got "%s"', $kty));
        }

        $alg = JwkAttributes::requireString($jwk, 'alg');
        if (array_key_exists('d', $jwk)) {
            throw new InvalidKeyException('JWK contains "d"; load via RsaPrivateKey::fromJwk instead');
        }

        $n = self::decodeBigInt($jwk, 'n');
        $e = self::decodeBigInt($jwk, 'e');
        $pem = self::publicPem($n, $e);

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
        $rsa = $this->details()['rsa'];
        /** @var array<string, mixed> $rsa */
        if (!isset($rsa['n']) || !is_string($rsa['n']) || !isset($rsa['e']) || !is_string($rsa['e'])) {
            // @codeCoverageIgnoreStart
            throw new InvalidKeyException('OpenSSL returned RSA details missing "n" or "e"');
            // @codeCoverageIgnoreEnd
        }

        $jwk = [
            'kty' => 'RSA',
            'alg' => $this->alg(),
            'n' => Base64Url::encode($rsa['n']),
            'e' => Base64Url::encode($rsa['e']),
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
     * @param non-empty-string $n modulus, raw big-endian bytes
     * @param non-empty-string $e public exponent, raw big-endian bytes
     */
    private static function publicPem(string $n, string $e): string
    {
        $der = Asn1::sequence(Asn1::integer($n) . Asn1::integer($e));

        return Asn1::toPem($der, 'RSA PUBLIC KEY');
    }

    /**
     * @throws InvalidKeyException
     */
    private static function assertRsa(OpenSSLAsymmetricKey $key): void
    {
        $details = openssl_pkey_get_details($key);
        if (!is_array($details)) {
            // @codeCoverageIgnoreStart
            throw new InvalidKeyException('OpenSSL could not read key details');
            // @codeCoverageIgnoreEnd
        }
        $type = $details['type'] ?? null;
        if ($type !== OPENSSL_KEYTYPE_RSA) {
            throw new InvalidKeyException('PEM is not an RSA key (RsaPublicKey rejects EC/DSA/Ed25519 input)');
        }
    }
}
