<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jws\Internal\B64Header;
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
        [$finalHeader, $signature] = $this->establish($algorithm, $header, $payload, $key);

        return CompactSerializer::serialize($finalHeader, $payload, $signature, $detached);
    }

    /**
     * RFC 7515 §7.2.2 flattened JSON serialization, single signature.
     *
     * @param array<string, mixed> $protectedHeader   integrity-protected header (`alg` may be omitted / filled in)
     * @param array<string, mixed> $unprotectedHeader the per-signature `header` member (not authenticated); names disjoint from the protected header
     *
     * @throws InvalidHeaderException if `alg` disagrees, header names collide, or `b64`/`crit` are malformed
     */
    public function signFlattened(
        SigningAlgorithm $algorithm,
        array $protectedHeader,
        string $payload,
        PrivateKey $key,
        array $unprotectedHeader = [],
        bool $detached = false,
    ): FlattenedJws {
        [$finalHeader, $signature] = $this->establish($algorithm, $protectedHeader, $payload, $key);

        return JsonSerializer::serializeFlattened($finalHeader, $unprotectedHeader, $payload, $signature, $detached);
    }

    /**
     * RFC 7515 §7.2.1 general JSON serialization, one or more signatures
     * over the same payload — possibly with different algorithms (the
     * RFC 7515 §A.6 case).
     *
     * Each signature's `alg`/`crit`/`b64` are independent except that
     * RFC 7797 §5.2 requires multi-signature JWS to agree on `b64`. The
     * structural serializer enforces that across the list.
     *
     * @param non-empty-list<SignatureSpec> $specs one row per signature to produce
     *
     * @throws InvalidHeaderException
     */
    public function signGeneral(
        array $specs,
        string $payload,
        bool $detached = false,
    ): GeneralJws {
        $rows = [];
        foreach ($specs as $spec) {
            [$finalHeader, $signature] = $this->establish($spec->algorithm, $spec->protectedHeader, $payload, $spec->key);
            $rows[] = [
                'protectedHeader' => $finalHeader,
                'unprotectedHeader' => $spec->unprotectedHeader,
                'signature' => $signature,
            ];
        }

        return JsonSerializer::serializeGeneral($rows, $payload, $detached);
    }

    /**
     * The shared validate-and-sign core behind all three serializations.
     * Returns the finalised protected header (with `alg` filled in or
     * checked) and the raw signature bytes.
     *
     * @param array<string, mixed> $header
     *
     * @return array{0: array<string, mixed>, 1: string} [finalHeader, signature]
     *
     * @throws InvalidHeaderException
     */
    private function establish(
        SigningAlgorithm $algorithm,
        array $header,
        string $payload,
        PrivateKey $key,
    ): array {
        $header = self::withAlg($header, $algorithm->name());
        B64Header::assertValid($header);
        $b64 = $header['b64'] ?? null;

        $encodedHeader = Base64Url::encode(Json::encode($header));
        // RFC 7797 §3: when `b64:false`, the payload is concatenated raw —
        // not base64url-encoded — into the signing input. Detached vs.
        // embedded is purely a wire-format choice and does not affect the
        // signing input (computed from the actual payload bytes either
        // way), so this helper is shared across all three serializations.
        $signingInput = $encodedHeader . '.' . ($b64 === false ? $payload : Base64Url::encode($payload));

        return [$header, $algorithm->sign($signingInput, $key)];
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
