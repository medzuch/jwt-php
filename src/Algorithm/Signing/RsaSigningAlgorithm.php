<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Key\PublicKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;

/**
 * Shared RSASSA-PKCS1-v1_5 sign/verify mechanics. One subclass per `alg`.
 *
 * Like {@see HmacAlgorithm}, this checks the key class, alg binding, and
 * `use`/`key_ops`. `sign()` accepts only {@see RsaPrivateKey}; `verify()`
 * accepts only {@see RsaPublicKey} — so an `RsaPrivateKey` cannot be used
 * to verify, and an `HmacKey` cannot reach this class through either path.
 *
 * The backing primitive is OpenSSL's `openssl_sign` / `openssl_verify` with
 * an `OPENSSL_ALGO_*` constant. `openssl_verify` returns `-1` on a backend
 * error (corrupted key, unsupported hash); we surface that as
 * {@see SignatureVerificationException} rather than coercing it to `false`,
 * because a backend error is not a "signature didn't match".
 */
abstract class RsaSigningAlgorithm implements SigningAlgorithm
{
    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::Rsa;
    }

    public function sign(string $input, PrivateKey $key): string
    {
        if (!$key instanceof RsaPrivateKey) {
            throw new KeyMismatchException(sprintf('%s requires RsaPrivateKey; got %s (RFC 8725 §3.1)', $this->name(), $key::class));
        }
        $key->assertAlgorithm($this->name());
        if (!$key->allowsOperation('sign')) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "sign" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)'));
        }

        self::drainOpensslErrors();

        $signature = '';
        if (!openssl_sign($input, $signature, $key->openSslKey(), $this->opensslAlgorithm())) {
            // @codeCoverageIgnoreStart
            // Reaching this path requires an OpenSSL internal failure on an
            // already-validated key resource; we cannot trigger it reliably
            // from tests on supported PHP versions.
            throw new SignatureVerificationException(self::opensslError(sprintf('openssl_sign failed for %s', $this->name())));
            // @codeCoverageIgnoreEnd
        }

        /** @var non-empty-string $signature */
        return $signature;
    }

    public function verify(string $input, string $signature, PublicKey $key): bool
    {
        if (!$key instanceof RsaPublicKey) {
            throw new KeyMismatchException(sprintf('%s requires RsaPublicKey; got %s (RFC 8725 §3.1)', $this->name(), $key::class));
        }
        $key->assertAlgorithm($this->name());
        if (!$key->allowsOperation('verify')) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "verify" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)'));
        }

        self::drainOpensslErrors();

        $result = openssl_verify($input, $signature, $key->openSslKey(), $this->opensslAlgorithm());
        if ($result === -1) {
            // @codeCoverageIgnoreStart
            throw new SignatureVerificationException(self::opensslError(sprintf('openssl_verify failed for %s', $this->name())));
            // @codeCoverageIgnoreEnd
        }

        return $result === 1;
    }

    /**
     * The `OPENSSL_ALGO_*` constant identifying this algorithm's hash.
     */
    abstract protected function opensslAlgorithm(): int;

    private static function drainOpensslErrors(): void
    {
        while (openssl_error_string() !== false) {
        }
    }

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
