<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\EcCurve;
use OpenSSLAsymmetricKey;

/**
 * Shared state for {@see EcPublicKey} and {@see EcPrivateKey}.
 *
 * Holds the parsed `OpenSSLAsymmetricKey` resource that the algorithm
 * layer will consume directly for sign/verify, plus a cached set of
 * key details and the resolved {@see EcCurve} metadata.
 *
 * The "one key, one algorithm" rule of RFC 8725 §3.1 is enforced at
 * construction: the algorithm-to-curve binding (ES256 ↔ P-256,
 * ES384 ↔ P-384, ES512 ↔ P-521) is mandatory.
 */
abstract class EcKey extends AsymmetricKey
{
    /** @var array<string, mixed> */
    private readonly array $details;

    private readonly EcCurve $curve;

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

        $expectedCurve = EcCurve::fromAlg($alg);

        $details = openssl_pkey_get_details($openSslKey);
        if (!is_array($details) || !array_key_exists('ec', $details) || !is_array($details['ec'])) {
            // @codeCoverageIgnoreStart
            throw new InvalidKeyException('OpenSSL could not extract EC key parameters');
            // @codeCoverageIgnoreEnd
        }

        $opensslCurve = $details['ec']['curve_name'] ?? null;
        if (!is_string($opensslCurve) || $opensslCurve === '') {
            // @codeCoverageIgnoreStart
            throw new InvalidKeyException('OpenSSL did not report a curve name for the EC key');
            // @codeCoverageIgnoreEnd
        }
        $actualCurve = EcCurve::fromOpensslName($opensslCurve);
        if ($actualCurve->jwkName !== $expectedCurve->jwkName) {
            throw new InvalidKeyException(sprintf('EC key on curve "%s" cannot be used with algorithm "%s" (RFC 7518 §3.4 requires %s)', $actualCurve->jwkName, $alg, $expectedCurve->jwkName));
        }

        $this->details = $details;
        $this->curve = $actualCurve;
    }

    /**
     * @internal consumed by the ECDSA signing/verifying algorithm classes
     */
    public function openSslKey(): OpenSSLAsymmetricKey
    {
        return $this->openSslKey;
    }

    public function curve(): EcCurve
    {
        return $this->curve;
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
