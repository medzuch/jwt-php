<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Key\Internal\EcCurve;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Key\PublicKey;
use Throwable;

/**
 * Shared ECDSA sign/verify mechanics. One subclass per `alg` (ES256/384/512).
 *
 * Like {@see HmacAlgorithm} and {@see RsaSigningAlgorithm}, this enforces
 * the key class, the algorithm-to-curve binding (RFC 7518 §3.4), and the
 * `use` / `key_ops` permissions. `sign()` accepts only {@see EcPrivateKey};
 * `verify()` accepts only {@see EcPublicKey}.
 *
 * OpenSSL emits ECDSA signatures as DER-encoded `SEQUENCE { INTEGER r,
 * INTEGER s }`. JOSE requires the raw concatenation `r || s`, each
 * left-padded to the curve coordinate size (RFC 7515 §3.1, RFC 7518 §3.4).
 * We translate between the two forms here so the rest of the JWS layer
 * stays format-agnostic.
 */
abstract class EcdsaSigningAlgorithm implements SigningAlgorithm
{
    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::Ecdsa;
    }

    public function sign(string $input, PrivateKey $key): string
    {
        if (!$key instanceof EcPrivateKey) {
            throw new KeyMismatchException(sprintf('%s requires EcPrivateKey; got %s (RFC 8725 §3.1)', $this->name(), $key::class));
        }
        $key->assertAlgorithm($this->name());
        if (!$key->allowsOperation('sign')) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "sign" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)'));
        }

        self::drainOpensslErrors();

        $derSignature = '';
        if (!openssl_sign($input, $derSignature, $key->openSslKey(), $this->opensslAlgorithm())) {
            // @codeCoverageIgnoreStart
            // @infection-ignore-all — reaching this path requires an OpenSSL
            // internal failure on an already-validated key resource; not
            // triggerable from tests on supported PHP versions.
            throw new SignatureVerificationException(self::opensslError(sprintf('openssl_sign failed for %s', $this->name())));
            // @codeCoverageIgnoreEnd
        }

        try {
            $raw = Asn1::ecdsaDerToRaw($derSignature, $key->curve()->coordSize);
            assert($raw !== '');

            return $raw;
        } catch (Throwable $e) {
            // @codeCoverageIgnoreStart
            // @infection-ignore-all — OpenSSL emits well-formed DER on
            // success; reaching this branch implies a backend defect.
            throw new SignatureVerificationException(sprintf('openssl_sign produced malformed ECDSA DER for %s: %s', $this->name(), $e->getMessage()), 0, $e);
            // @codeCoverageIgnoreEnd
        }
    }

    public function verify(string $input, string $signature, PublicKey $key): bool
    {
        if (!$key instanceof EcPublicKey) {
            throw new KeyMismatchException(sprintf('%s requires EcPublicKey; got %s (RFC 8725 §3.1)', $this->name(), $key::class));
        }
        $key->assertAlgorithm($this->name());
        if (!$key->allowsOperation('verify')) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "verify" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)'));
        }

        // A signature of the wrong length cannot be valid for this curve;
        // refuse early so attackers can't probe by sending malformed input.
        $expected = 2 * $this->curve()->coordSize;
        if (strlen($signature) !== $expected) {
            return false;
        }

        try {
            $derSignature = Asn1::ecdsaRawToDer($signature, $this->curve()->coordSize);
        } catch (Throwable) {
            // @codeCoverageIgnoreStart
            // @infection-ignore-all — the length check above already covers
            // every input ecdsaRawToDer can reject.
            return false;
            // @codeCoverageIgnoreEnd
        }

        self::drainOpensslErrors();

        $result = openssl_verify($input, $derSignature, $key->openSslKey(), $this->opensslAlgorithm());
        if ($result === -1) {
            // @codeCoverageIgnoreStart
            // @infection-ignore-all — openssl_verify returns -1 only on
            // backend errors against an already-validated key; cannot
            // reliably trigger from tests.
            throw new SignatureVerificationException(self::opensslError(sprintf('openssl_verify failed for %s', $this->name())));
            // @codeCoverageIgnoreEnd
        }

        return $result === 1;
    }

    /**
     * The `OPENSSL_ALGO_*` constant identifying this algorithm's hash.
     */
    abstract protected function opensslAlgorithm(): int;

    /**
     * The {@see EcCurve} this algorithm is bound to.
     */
    abstract protected function curve(): EcCurve;

    private static function drainOpensslErrors(): void
    {
        while (openssl_error_string() !== false) {
        }
    }

    /**
     * Only invoked from `@codeCoverageIgnore`d failure paths in `sign()`
     * and `verify()`, so the body cannot be exercised from tests either.
     *
     * @codeCoverageIgnore
     * @infection-ignore-all
     */
    private static function opensslError(string $context): string
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
