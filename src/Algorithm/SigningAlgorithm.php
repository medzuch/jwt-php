<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm;

use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Key\PublicKey;

/**
 * Contract for JWS signing algorithms.
 *
 * The parameter types are the {@see PublicKey} / {@see PrivateKey} markers
 * (RFC 8725 §3.1 "one key, one algorithm"). Each concrete algorithm narrows
 * to its supported key class and throws {@see KeyMismatchException} on a
 * cross-family key — this is the McLean RS→HS confusion mitigation enforced
 * at the type system level.
 *
 * `verify()` returns `false` on a clean signature mismatch (the expected,
 * non-exceptional outcome). It throws only when the key is the wrong kind
 * of object or the crypto backend itself fails.
 */
interface SigningAlgorithm extends Algorithm
{
    /**
     * Produce the raw signature bytes over `$input` (the JWS signing input,
     * `BASE64URL(header) || "." || BASE64URL(payload)`).
     *
     * @return non-empty-string raw signature octets, ready to base64url-encode
     *
     * @throws KeyMismatchException if `$key` is not of this algorithm's expected class or alg binding
     */
    public function sign(string $input, PrivateKey $key): string;

    /**
     * Constant-time comparison of `$signature` against the locally recomputed
     * MAC / signature over `$input`.
     *
     * @throws KeyMismatchException if `$key` is not of this algorithm's expected class or alg binding
     */
    public function verify(string $input, string $signature, PublicKey $key): bool;
}
