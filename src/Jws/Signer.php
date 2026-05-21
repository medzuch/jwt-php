<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;

/**
 * Produces a compact JWS from a protected header, payload, algorithm, and
 * signing key (RFC 7515 §5.1).
 *
 * The signer is intentionally thin — it composes pieces other layers have
 * already validated. Concretely it:
 *
 *   1. Forces the `alg` header to match `$algorithm->name()`. If the caller
 *      passed an `alg` that disagrees, that is a programming error worth
 *      surfacing (silently overwriting would hide a bug; obeying the caller
 *      would let a builder cause Verifier failures downstream).
 *   2. Builds the signing input per RFC 7515 §5.1:
 *      `BASE64URL(UTF8(protected-header)) || "." || BASE64URL(payload)`.
 *   3. Delegates the actual signature computation to the algorithm strategy,
 *      which is also where key class / `alg` binding / `key_ops` are checked
 *      (see Layer 3 from PR #3).
 *   4. Wraps everything in {@see CompactSerializer::serialize()}.
 *
 * The Signer never reads `kid`, `typ`, etc.; those are passed through into
 * the header. The JWT API layer (PR #5) is responsible for setting them.
 */
final class Signer
{
    /**
     * @param array<string, mixed> $header protected header. `alg` may be
     *                                     omitted (Signer fills it in) or
     *                                     provided (must match algorithm).
     * @param string $payload raw payload bytes — the JWS layer
     *                        is payload-agnostic
     *
     * @throws InvalidHeaderException if a caller-supplied `alg` disagrees with
     *                                $algorithm->name()
     */
    public function sign(
        SigningAlgorithm $algorithm,
        array $header,
        string $payload,
        PrivateKey $key,
    ): CompactJws {
        $header = self::withAlg($header, $algorithm->name());

        $encodedHeader = Base64Url::encode(Json::encode($header));
        $encodedPayload = Base64Url::encode($payload);
        $signingInput = $encodedHeader . '.' . $encodedPayload;

        $signature = $algorithm->sign($signingInput, $key);

        return new CompactJws($encodedHeader . '.' . $encodedPayload . '.' . Base64Url::encode($signature));
    }

    /**
     * @param array<string, mixed> $header
     *
     * @return array<string, mixed>
     *
     * @throws InvalidHeaderException
     */
    private static function withAlg(array $header, string $algName): array
    {
        if (array_key_exists('alg', $header) && $header['alg'] !== $algName) {
            throw new InvalidHeaderException(sprintf('Header "alg" %s does not match signing algorithm %s', self::describe($header['alg']), $algName));
        }

        $header['alg'] = $algName;

        return $header;
    }

    private static function describe(mixed $value): string
    {
        return match (true) {
            $value === null => 'null',
            is_string($value) => '"' . $value . '"',
            default => '(' . get_debug_type($value) . ')',
        };
    }
}
