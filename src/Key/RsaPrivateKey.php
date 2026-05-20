<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Primitives\Base64Url;
use OpenSSLAsymmetricKey;

use function array_key_exists;
use function is_array;
use function is_string;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function sprintf;

use const OPENSSL_KEYTYPE_RSA;

/**
 * RSA private key bound to one of RS256, RS384, RS512.
 *
 * Carries all eight CRT components so that JWK export is lossless.
 */
final class RsaPrivateKey extends RsaKey implements PrivateKey
{
    private const REQUIRED_JWK_PARAMS = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'];

    /**
     * Load a private key from PEM ("-----BEGIN PRIVATE KEY-----" or
     * "-----BEGIN RSA PRIVATE KEY-----"). Encrypted PEMs are not
     * supported in Phase 1 — pass an already-decrypted key.
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
            throw new InvalidKeyException(self::opensslError('Failed to load RSA private key from PEM'));
        }

        self::assertRsa($key);

        return new self($key, $alg, $kid, $use, $keyOps);
    }

    /**
     * Build a private RSA key from an RFC 7517 JWK with `kty:"RSA"` and
     * the full CRT parameter set.
     *
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function fromJwk(array $jwk): self
    {
        $kty = JwkAttributes::requireString($jwk, 'kty');
        if ($kty !== 'RSA') {
            throw new InvalidKeyException(sprintf('RsaPrivateKey::fromJwk requires kty "RSA", got "%s"', $kty));
        }

        $alg = JwkAttributes::requireString($jwk, 'alg');

        $components = [];
        foreach (self::REQUIRED_JWK_PARAMS as $param) {
            $components[$param] = self::decodeBigInt($jwk, $param);
        }

        $pem = self::privatePem($components);

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

        // OpenSSL names map to JWK names per RFC 7518 §6.3.2:
        //   n→n, e→e, d→d, p→p, q→q, dmp1→dp, dmq1→dq, iqmp→qi
        $map = [
            'n' => 'n', 'e' => 'e', 'd' => 'd',
            'p' => 'p', 'q' => 'q',
            'dmp1' => 'dp', 'dmq1' => 'dq', 'iqmp' => 'qi',
        ];

        $jwk = ['kty' => 'RSA', 'alg' => $this->alg()];
        foreach ($map as $openSslName => $jwkName) {
            if (!isset($rsa[$openSslName]) || !is_string($rsa[$openSslName])) {
                // @codeCoverageIgnoreStart
                throw new InvalidKeyException(sprintf('OpenSSL returned RSA details missing "%s"', $openSslName));
                // @codeCoverageIgnoreEnd
            }
            $jwk[$jwkName] = Base64Url::encode($rsa[$openSslName]);
        }

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
     * Public counterpart of this private key (drops `d` and the CRT
     * parameters).
     *
     * @throws InvalidKeyException
     */
    public function toPublicKey(): RsaPublicKey
    {
        $public = $this->toJwk();
        unset($public['d'], $public['p'], $public['q'], $public['dp'], $public['dq'], $public['qi']);

        return RsaPublicKey::fromJwk($public);
    }

    /**
     * Build a PKCS#1 RSAPrivateKey PEM from the eight components.
     *
     * @param array{n: non-empty-string, e: non-empty-string, d: non-empty-string, p: non-empty-string, q: non-empty-string, dp: non-empty-string, dq: non-empty-string, qi: non-empty-string} $c
     */
    private static function privatePem(array $c): string
    {
        // RFC 8017 §A.1.2 — RSAPrivateKey ::= SEQUENCE {
        //     version, modulus, publicExponent, privateExponent,
        //     prime1, prime2, exponent1, exponent2, coefficient }
        $version = Asn1::integer("\x00");
        $contents = $version
            . Asn1::integer($c['n'])
            . Asn1::integer($c['e'])
            . Asn1::integer($c['d'])
            . Asn1::integer($c['p'])
            . Asn1::integer($c['q'])
            . Asn1::integer($c['dp'])
            . Asn1::integer($c['dq'])
            . Asn1::integer($c['qi']);

        return Asn1::toPem(Asn1::sequence($contents), 'RSA PRIVATE KEY');
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
            throw new InvalidKeyException('PEM is not an RSA key (RsaPrivateKey rejects EC/DSA/Ed25519 input)');
        }
        if (!array_key_exists('rsa', $details)
            || !is_array($details['rsa'])
            || !array_key_exists('d', $details['rsa'])
        ) {
            throw new InvalidKeyException('PEM does not include private parameters (use RsaPublicKey::fromPem for public keys)');
        }
    }
}
