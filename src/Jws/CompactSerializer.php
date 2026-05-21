<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;

use function count;
use function explode;
use function is_array;
use function is_string;
use function sprintf;

/**
 * Pure structural serializer for the JWS Compact Serialization
 * (RFC 7515 §7.1).
 *
 * Has no knowledge of keys, algorithms, or claims. Its only job is to turn
 * `(header, payload, signature)` into the canonical
 * `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)` string and
 * back. {@see Signer} and {@see Verifier} are what add the crypto on top.
 *
 * Splitting this out keeps {@see Verifier} unit-testable without
 * constructing real keys, and keeps the JWT layer (PR #5) free to call
 * `deserialize()` from a different entry point (its two-phase parse API
 * needs the header before crypto runs).
 */
final class CompactSerializer
{
    /** @codeCoverageIgnore */
    private function __construct()
    {
    }

    /**
     * Encode `(header, payload, signature)` as a compact JWS.
     *
     * @param array<string, mixed> $header protected header
     * @param string $payload raw payload bytes (the JWS layer is
     *                        payload-agnostic; the JWT layer hands
     *                        it JSON-encoded claims)
     * @param string $signature raw signature bytes from
     *                          {@see \Medzuch\Jwt\Algorithm\SigningAlgorithm::sign()}
     *
     * @throws MalformedJwtException on JSON-encode failure
     */
    public static function serialize(array $header, string $payload, string $signature): CompactJws
    {
        $encodedHeader = Base64Url::encode(Json::encode($header));
        $encodedPayload = Base64Url::encode($payload);
        $encodedSignature = Base64Url::encode($signature);

        return new CompactJws($encodedHeader . '.' . $encodedPayload . '.' . $encodedSignature);
    }

    /**
     * Decode a compact JWS string into its constituent pieces and the
     * parsed protected header. No crypto runs.
     *
     * Refusals at this stage:
     *   - Wrong number of `.`-separated segments → {@see MalformedJwtException}.
     *   - Any segment not valid base64url → {@see MalformedJwtException}.
     *   - Header not a JSON object → {@see MalformedJwtException}.
     *   - Header missing `alg` or `alg` not a string → {@see InvalidHeaderException}
     *     (the header MUST carry `alg`; refusing here is cheap and keeps the
     *     {@see Verifier} branches clean).
     *
     * @throws MalformedJwtException
     * @throws InvalidHeaderException
     */
    public static function deserialize(string $compact): ParsedJws
    {
        if ($compact === '') {
            throw new MalformedJwtException('Compact JWS is empty');
        }

        $segments = explode('.', $compact);
        if (count($segments) !== 3) {
            throw new MalformedJwtException(sprintf('Compact JWS must have exactly 3 dot-separated segments; got %d', count($segments)));
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $segments;

        if ($encodedHeader === '') {
            throw new MalformedJwtException('Compact JWS header segment is empty');
        }

        // A signed JWS must have a signature segment; the empty-signature
        // form is unique to `alg:none`, which is not handled at this layer.
        if ($encodedSignature === '') {
            throw new MalformedJwtException('Compact JWS signature segment is empty');
        }

        $headerJson = Base64Url::decode($encodedHeader);
        $payload = Base64Url::decode($encodedPayload);
        $signature = Base64Url::decode($encodedSignature);

        $header = Json::decode($headerJson);

        self::assertHeaderShape($header);

        return new ParsedJws(
            $encodedHeader,
            $encodedPayload,
            $encodedSignature,
            $header,
            $payload,
            $signature,
        );
    }

    /**
     * @param array<string, mixed> $header
     *
     * @throws InvalidHeaderException
     */
    private static function assertHeaderShape(array $header): void
    {
        if (!isset($header['alg'])) {
            throw new InvalidHeaderException('Protected header is missing required "alg"');
        }
        if (!is_string($header['alg']) || $header['alg'] === '') {
            throw new InvalidHeaderException('Protected header "alg" must be a non-empty string');
        }

        // Anything else that's structurally invalid in the protected header is
        // refused by {@see Verifier} so this method stays a pure structural check.
        // We do reject one thing here: a stray `.` inside any segment via the
        // earlier split would have produced too many segments; an embedded
        // newline inside the base64url payload would have failed Base64Url::decode.
        // Both are handled upstream.
        if (isset($header['typ']) && !is_string($header['typ'])) {
            throw new InvalidHeaderException('Protected header "typ" must be a string when present');
        }
        if (isset($header['cty']) && !is_string($header['cty'])) {
            throw new InvalidHeaderException('Protected header "cty" must be a string when present');
        }
        if (isset($header['kid']) && !is_string($header['kid'])) {
            throw new InvalidHeaderException('Protected header "kid" must be a string when present');
        }
        if (isset($header['crit']) && !self::isStringList($header['crit'])) {
            throw new InvalidHeaderException('Protected header "crit" must be a non-empty list of strings (RFC 7515 §4.1.11)');
        }
    }

    private static function isStringList(mixed $value): bool
    {
        if (!is_array($value) || $value === []) {
            return false;
        }
        $expected = 0;
        foreach ($value as $i => $entry) {
            if ($i !== $expected || !is_string($entry) || $entry === '') {
                return false;
            }
            ++$expected;
        }

        return true;
    }
}
