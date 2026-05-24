<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Key\PublicKey;
use Medzuch\Jwt\Primitives\ConstantTime;

/**
 * Shared HMAC sign/verify mechanics. One concrete subclass per `alg`.
 *
 * Both `sign()` and `verify()` enforce:
 * - Key class is {@see HmacKey} (refuses an asymmetric public key being
 *   smuggled in as an HMAC secret — the McLean RS→HS confusion attack).
 * - Key's bound `alg` matches this algorithm's name (RFC 8725 §3.1).
 * - Key's `key_ops` / `use` permits the requested operation (RFC 7517 §4.3).
 *
 * Constant-time comparison via {@see ConstantTime::equals} on the verify
 * path (T12).
 */
abstract class HmacAlgorithm implements SigningAlgorithm
{
    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::Hmac;
    }

    public function sign(string $input, PrivateKey $key): string
    {
        $hmacKey = self::assertHmacKey($key);
        $this->assertBindings($hmacKey, 'sign');

        return self::compute($this->hashAlgorithm(), $input, $hmacKey->bytes());
    }

    public function verify(string $input, string $signature, PublicKey $key): bool
    {
        $hmacKey = self::assertHmacKey($key);
        $this->assertBindings($hmacKey, 'verify');

        $expected = self::compute($this->hashAlgorithm(), $input, $hmacKey->bytes());

        return ConstantTime::equals($expected, $signature);
    }

    /**
     * The `hash_hmac` algorithm name backing this `alg`, e.g. `"sha256"`.
     *
     * @return non-empty-string
     */
    abstract protected function hashAlgorithm(): string;

    /**
     * @throws KeyMismatchException
     */
    private static function assertHmacKey(PublicKey|PrivateKey $key): HmacKey
    {
        if (!$key instanceof HmacKey) {
            throw new KeyMismatchException(sprintf('HMAC algorithm requires HmacKey; got %s (RFC 8725 §3.1, McLean confusion mitigation)', $key::class));
        }

        return $key;
    }

    /**
     * @throws KeyMismatchException
     */
    private function assertBindings(HmacKey $key, string $op): void
    {
        $key->assertAlgorithm($this->name());

        if (!$key->allowsOperation($op)) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "%s" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)', $op));
        }
    }

    /**
     * @param non-empty-string $algo
     *
     * @return non-empty-string
     */
    private static function compute(string $algo, string $input, string $secret): string
    {
        // `hash_hmac` with $binary=true returns the raw MAC bytes; output
        // length is fixed by $algo (32/48/64 for sha256/384/512).
        return hash_hmac($algo, $input, $secret, true);
    }
}
