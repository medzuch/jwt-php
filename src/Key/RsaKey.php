<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use OpenSSLAsymmetricKey;

use function array_key_exists;
use function in_array;
use function is_array;
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
}
