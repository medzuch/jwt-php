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
 * signing key (RFC 7515 §5.1, with the RFC 7797 `b64:false` variant).
 *
 * The signer is intentionally thin — it composes pieces other layers have
 * already validated. Concretely it:
 *
 *   1. Forces the `alg` header to match `$algorithm->name()`. If the caller
 *      passed an `alg` that disagrees, that is a programming error worth
 *      surfacing (silently overwriting would hide a bug; obeying the caller
 *      would let a builder cause Verifier failures downstream).
 *   2. Reads the `b64` header (RFC 7797 §3). When absent or `true` the
 *      signing input is the standard `BASE64URL(UTF8(header)) || "." ||
 *      BASE64URL(payload)`. When `false` the payload feeds the signing
 *      input unencoded as `BASE64URL(UTF8(header)) || "." || payload`, and
 *      the Signer enforces `crit` includes `"b64"` (RFC 7797 §6).
 *   3. Optionally produces the detached form (RFC 7515 Appendix F) when
 *      `$detached === true`: the on-the-wire middle segment is empty, the
 *      payload is conveyed out of band, and the signing input is computed
 *      from the actual payload bytes either way.
 *   4. Delegates the actual signature computation to the algorithm strategy,
 *      which is also where key class / `alg` binding / `key_ops` are checked.
 *   5. Wraps everything in {@see CompactSerializer::serialize()}.
 *
 * The Signer never reads `kid`, `typ`, etc.; those are passed through into
 * the header. The JWT layer is responsible for setting them — and for
 * refusing `b64:false` (RFC 7797 §7); the JWT-level guard rejects it before
 * the Signer is ever called.
 */
final class Signer
{
    /**
     * @param array<string, mixed> $header protected header. `alg` may be
     *                                     omitted (Signer fills it in) or
     *                                     provided (must match algorithm).
     *                                     Set `b64 => false` to opt into
     *                                     the RFC 7797 unencoded payload
     *                                     variant; `crit` must then include
     *                                     `"b64"`.
     * @param string $payload raw payload bytes — the JWS layer
     *                        is payload-agnostic
     * @param bool $detached when true, the middle segment of the compact
     *                       form is emitted empty; the caller delivers the
     *                       payload out of band and verifies via
     *                       {@see Verifier::verifyDetached()}
     *
     * @throws InvalidHeaderException if a caller-supplied `alg` disagrees with
     *                                $algorithm->name(), or if `b64:false` is
     *                                set without `crit` listing `"b64"`
     */
    public function sign(
        SigningAlgorithm $algorithm,
        array $header,
        string $payload,
        PrivateKey $key,
        bool $detached = false,
    ): CompactJws {
        $header = self::withAlg($header, $algorithm->name());
        $b64 = self::b64Mode($header);
        if ($b64 === false) {
            self::assertB64Critical($header);
        }

        $encodedHeader = Base64Url::encode(Json::encode($header));
        // RFC 7797 §3: when `b64:false`, the payload is concatenated raw —
        // not base64url-encoded — into the signing input. The compact-
        // serialization middle segment likewise carries the raw payload (or
        // empty, for detached). Computing the signing input from the actual
        // payload bytes makes the detached case fall out for free: signing
        // input is independent of what does or does not appear on the wire.
        $signingInput = $encodedHeader . '.' . ($b64 === false ? $payload : Base64Url::encode($payload));

        $signature = $algorithm->sign($signingInput, $key);

        return CompactSerializer::serialize($header, $payload, $signature, $detached);
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

    /**
     * @param array<string, mixed> $header
     *
     * @throws InvalidHeaderException
     */
    private static function b64Mode(array $header): ?bool
    {
        if (!array_key_exists('b64', $header)) {
            return null;
        }
        $value = $header['b64'];
        if (!is_bool($value)) {
            throw new InvalidHeaderException('Header "b64" must be a boolean (RFC 7797 §3)');
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $header
     *
     * @throws InvalidHeaderException
     */
    private static function assertB64Critical(array $header): void
    {
        $crit = $header['crit'] ?? null;
        if (!is_array($crit) || !in_array('b64', $crit, true)) {
            throw new InvalidHeaderException('Header "b64":false requires "crit" to include "b64" (RFC 7797 §6)');
        }
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
