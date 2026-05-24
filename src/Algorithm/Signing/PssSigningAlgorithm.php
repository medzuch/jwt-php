<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\Internal\Pss;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Key\PublicKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;

/**
 * Shared RSASSA-PSS sign/verify mechanics — one subclass per `alg`.
 *
 * PHP 8.3 + OpenSSL 3.x does not expose PSS through `openssl_sign`, so we
 * build the EMSA-PSS encoding ourselves ({@see Pss::encode()}) and feed it
 * through the raw RSA primitive via `openssl_private_encrypt` /
 * `openssl_public_decrypt` with `OPENSSL_NO_PADDING`. The padding scheme
 * (PSS) lives entirely in {@see Pss}; OpenSSL just performs the modular
 * exponentiation.
 *
 * Algorithm family is reported as {@see AlgorithmFamily::Rsa} because PSS
 * shares its key material with RS* — the same {@see RsaPrivateKey} /
 * {@see RsaPublicKey} can be bound to either family, and the alg-binding
 * check at {@see \Medzuch\Jwt\Key\Key::assertAlgorithm()} keeps confusion
 * at bay.
 *
 * Salt length follows RFC 7518 §3.5: sLen = hLen.
 */
abstract class PssSigningAlgorithm implements SigningAlgorithm
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

        $hashAlgo = $this->hashAlgorithm();
        $hLen = $this->hashByteLength();
        $modBits = $key->bits();
        // RFC 8017 §9.1: emBits = modBits - 1 so the encoded message, when
        // treated as a big-endian integer, is guaranteed to be < n.
        $emBits = $modBits - 1;
        $emLen = intdiv($emBits + 7, 8);
        $modBytes = intdiv($modBits, 8);

        $em = Pss::encode($input, $hashAlgo, $emBits, $hLen);

        self::drainOpensslErrors();

        // openssl_private_encrypt with OPENSSL_NO_PADDING requires input of
        // exactly modulus-byte length. For modBits divisible by 8, emLen ==
        // modBytes; for other moduli we'd need to left-pad. Library refuses
        // non-byte-aligned keys (MIN_BITS = 2048 is always byte-aligned).
        if ($emLen !== $modBytes) {
            $em = str_repeat("\x00", $modBytes - $emLen) . $em;
        }

        $signature = '';
        if (!openssl_private_encrypt($em, $signature, $key->openSslKey(), OPENSSL_NO_PADDING)) {
            // @codeCoverageIgnoreStart
            // @infection-ignore-all — reaching this path requires an OpenSSL
            // internal failure on an already-validated key; not triggerable.
            throw new SignatureVerificationException(self::opensslError(sprintf('openssl_private_encrypt failed for %s', $this->name())));
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

        $modBits = $key->bits();
        $modBytes = intdiv($modBits, 8);
        // A signature of the wrong length cannot be valid; refuse early so
        // attackers can't probe the raw-RSA layer with malformed input.
        // Not constant-time w.r.t. length — verify operates only on public
        // material, so no secret-dependent timing path exists.
        if (strlen($signature) !== $modBytes) {
            return false;
        }

        self::drainOpensslErrors();

        $em = '';
        if (!openssl_public_decrypt($signature, $em, $key->openSslKey(), OPENSSL_NO_PADDING)) {
            // OpenSSL refuses the raw-RSA operation (e.g. signature >= n);
            // surface as a normal verification failure, not an exception.
            // @infection-ignore-all — the success path is exercised by
            // every passing verify test.
            return false;
        }

        $emBits = $modBits - 1;
        $emLen = intdiv($emBits + 7, 8);
        // Strip the leading zero byte the encrypt path may have added when
        // emLen != modBytes (byte-aligned moduli only — but the leading
        // octet should always be 0x00 in that case).
        if (strlen($em) === $modBytes && $emLen !== $modBytes) {
            $em = substr($em, $modBytes - $emLen);
        }

        return Pss::verify($input, $em, $this->hashAlgorithm(), $emBits, $this->hashByteLength());
    }

    /**
     * Hash algorithm name accepted by hash() (e.g. "sha256").
     *
     * @return non-empty-string
     */
    abstract protected function hashAlgorithm(): string;

    /**
     * @return positive-int hash output length in bytes (sLen = this)
     */
    abstract protected function hashByteLength(): int;

    private static function drainOpensslErrors(): void
    {
        while (openssl_error_string() !== false) {
        }
    }

    /**
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
