<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Primitives\Base64Url;
use OpenSSLAsymmetricKey;
use Throwable;

use function array_key_exists;
use function implode;
use function in_array;
use function is_array;
use function is_int;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function sprintf;

/**
 * Shared state for {@see RsaPublicKey} and {@see RsaPrivateKey}.
 *
 * Holds the parsed `OpenSSLAsymmetricKey` resource that the algorithm
 * layer will consume directly for sign/verify, plus a cached set of
 * key details for JWK export.
 */
abstract class RsaKey extends AsymmetricKey
{
    private const ALLOWED_ALGS = ['RS256', 'RS384', 'RS512'];

    /**
     * Minimum modulus length, per NIST SP 800-131A Rev. 2 (2019) and
     * current OpenSSL defaults. 1024-bit RSA has been factorable on
     * commodity hardware for years.
     */
    private const MIN_BITS = 2048;

    /** @var array<string, mixed> */
    private readonly array $details;

    /**
     * @param list<string>|null $keyOps
     *
     * @throws InvalidKeyException
     */
    protected function __construct(
        private readonly OpenSSLAsymmetricKey $openSslKey,
        string $alg,
        ?string $kid = null,
        ?KeyUse $use = null,
        ?array $keyOps = null,
    ) {
        parent::__construct($alg, $kid, $use, $keyOps);

        if (!in_array($alg, self::ALLOWED_ALGS, true)) {
            throw new InvalidKeyException(sprintf('RsaKey supports RS256/RS384/RS512, got "%s"', $alg));
        }

        $details = openssl_pkey_get_details($openSslKey);
        if (!is_array($details) || !array_key_exists('rsa', $details) || !is_array($details['rsa'])) {
            // @codeCoverageIgnoreStart
            // Defensive: openssl_pkey_get_details only fails on a corrupted
            // resource we have already accepted via openssl_pkey_get_*; in
            // practice the constructor inputs come from openssl_pkey_get_*
            // returning a valid handle.
            throw new InvalidKeyException('OpenSSL could not extract RSA key parameters');
            // @codeCoverageIgnoreEnd
        }

        $bits = $details['bits'] ?? null;
        if (!is_int($bits) || $bits < self::MIN_BITS) {
            throw new InvalidKeyException(sprintf('RSA key must be at least %d bits (NIST SP 800-131A Rev. 2); got %s', self::MIN_BITS, is_int($bits) ? (string) $bits : 'unknown'));
        }

        $this->details = $details;
    }

    /**
     * @internal consumed by the RSA signing/verifying algorithm classes
     */
    public function openSslKey(): OpenSSLAsymmetricKey
    {
        return $this->openSslKey;
    }

    /**
     * @return array<string, mixed> details as returned by openssl_pkey_get_details
     *
     * @internal
     */
    protected function details(): array
    {
        return $this->details;
    }

    /**
     * Decode an RSA component (modulus, exponent, CRT factor) from a JWK.
     *
     * @param array<string, mixed> $jwk
     *
     * @return non-empty-string raw big-endian bytes
     *
     * @throws InvalidKeyException
     */
    protected static function decodeBigInt(array $jwk, string $param): string
    {
        $encoded = JwkAttributes::requireString($jwk, $param);

        try {
            $bytes = Base64Url::decode($encoded);
        } catch (Throwable $e) {
            throw new InvalidKeyException(sprintf('JWK "%s" is not valid base64url', $param), 0, $e);
        }

        if ($bytes === '') {
            throw new InvalidKeyException(sprintf('JWK "%s" decoded to empty bytes', $param));
        }

        return $bytes;
    }

    /**
     * Drain the OpenSSL error queue and return $context with any messages appended.
     */
    protected static function opensslError(string $context): string
    {
        $messages = [];
        while (($msg = openssl_error_string()) !== false) {
            $messages[] = $msg;
        }
        if ($messages === []) {
            return $context;
        }

        return $context . ': ' . implode('; ', $messages);
    }
}
