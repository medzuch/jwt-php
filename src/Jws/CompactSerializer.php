<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jws\Internal\B64Header;
use Medzuch\Jwt\Jws\Internal\HeaderShape;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;

/**
 * Pure structural serializer for the JWS Compact Serialization
 * (RFC 7515 §7.1) — including the RFC 7797 `b64:false` variant.
 *
 * Has no knowledge of keys, algorithms, or claims. Its only job is to turn
 * `(header, payload, signature)` into the canonical
 * `BASE64URL(header).<payload>.BASE64URL(signature)` string and back, where
 * `<payload>` is `BASE64URL(payload)` by default, the raw payload bytes when
 * the header declares `b64:false` (RFC 7797 §3), and empty when the payload
 * is conveyed out of band (detached, RFC 7515 Appendix F). {@see Signer}
 * and {@see Verifier} are what add the crypto on top.
 *
 * Splitting this out keeps {@see Verifier} unit-testable without
 * constructing real keys, and keeps the JWT layer free to call
 * `deserialize()` from a different entry point (its two-phase parse API
 * needs the header before crypto runs).
 */
final class CompactSerializer
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * Encode `(header, payload, signature)` as a compact JWS.
     *
     * The serialization variant is chosen from the header and the
     * `$detached` flag:
     *   - `b64` absent or `b64:true` → middle segment is `BASE64URL(payload)`.
     *   - `b64:false` → middle segment is the raw payload bytes (RFC 7797 §3).
     *   - `$detached === true` → middle segment is empty regardless; the
     *     payload is conveyed out of band.
     *
     * When `b64:false` is in the header (RFC 7797), the header MUST also
     * carry `crit` containing `"b64"` — the Signer enforces that, but this
     * serializer is structural and trusts the inputs.
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
    public static function serialize(array $header, string $payload, string $signature, bool $detached = false): CompactJws
    {
        $encodedHeader = Base64Url::encode(Json::encode($header));
        $encodedPayload = $detached ? '' : self::encodePayload($payload, self::b64Mode($header));
        $encodedSignature = Base64Url::encode($signature);

        return new CompactJws($encodedHeader . '.' . $encodedPayload . '.' . $encodedSignature);
    }

    /**
     * Decode a compact JWS string into its constituent pieces and the
     * parsed protected header. No crypto runs.
     *
     * Splitting rule: the first `.` and the last `.` mark the segment
     * boundaries. That works for every case the spec allows — standard
     * three-segment, detached (empty middle), and the RFC 7797 §5.2
     * embedded-unencoded form where the payload itself may contain `.`
     * characters (the example in RFC 7797 §4.1 has payload `$.02`). The
     * RFC explicitly notes that detached + JSON Serialization are the
     * unambiguous options here; we accept the embedded form too because
     * the published vector does.
     *
     * Refusals at this stage:
     *   - Fewer than two `.` separators, or empty header / empty signature
     *     segment → {@see MalformedJwtException}.
     *   - Any segment that should be base64url-decodable but is not (the
     *     header, the signature, the payload when `b64` is true/absent) →
     *     {@see MalformedJwtException}.
     *   - Header not a JSON object → {@see MalformedJwtException}.
     *   - Header missing `alg`, or `alg` not a string → {@see InvalidHeaderException}.
     *   - `b64:false` declared but `crit` missing `"b64"`, or `crit`
     *     containing anything other than `"b64"` → {@see InvalidHeaderException}
     *     (RFC 7797 §6 + RFC 7515 §4.1.11).
     *   - `b64` present with a non-boolean value → {@see InvalidHeaderException}.
     *
     * @throws MalformedJwtException
     * @throws InvalidHeaderException
     */
    public static function deserialize(string $compact): ParsedJws
    {
        if ($compact === '') {
            throw new MalformedJwtException('Compact JWS is empty');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = self::splitSegments($compact);

        if ($encodedHeader === '') {
            throw new MalformedJwtException('Compact JWS header segment is empty');
        }
        // A signed JWS must have a signature segment; the empty-signature
        // form is unique to `alg:none`, which is not handled at this layer.
        if ($encodedSignature === '') {
            throw new MalformedJwtException('Compact JWS signature segment is empty');
        }

        $headerJson = Base64Url::decode($encodedHeader);
        $signature = Base64Url::decode($encodedSignature);

        $header = Json::decode($headerJson);
        HeaderShape::assertProtected($header);

        // The full RFC 7797 + §4.1.11 b64/crit coupling — shared with
        // Signer and Verifier so a token from one is always parseable by
        // the other.
        B64Header::assertValid($header);
        $b64 = $header['b64'] ?? null;

        // Decode the payload according to the b64 mode. When the middle
        // segment is empty the payload is detached (RFC 7515 Appendix F)
        // — the structural parse returns an empty payload here; consumers
        // who need to verify a detached JWS pass the external payload to
        // {@see Verifier::verifyDetached()}.
        $payload = $encodedPayload === '' || $b64 === false
            ? $encodedPayload
            : Base64Url::decode($encodedPayload);

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
     * Split on the first and last `.` so an embedded-unencoded payload that
     * itself contains `.` characters (RFC 7797 §5.2) still parses cleanly.
     *
     * @return array{0: string, 1: string, 2: string}
     *
     * @throws MalformedJwtException
     */
    private static function splitSegments(string $compact): array
    {
        $first = strpos($compact, '.');
        $last = strrpos($compact, '.');
        if ($first === false || $last === false || $first === $last) {
            throw new MalformedJwtException('Compact JWS must have at least two "." separators (header.payload.signature)');
        }

        return [
            substr($compact, 0, $first),
            substr($compact, $first + 1, $last - $first - 1),
            substr($compact, $last + 1),
        ];
    }

    private static function encodePayload(string $payload, ?bool $b64): string
    {
        return $b64 === false ? $payload : Base64Url::encode($payload);
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
            throw new InvalidHeaderException('Protected header "b64" must be a boolean (RFC 7797 §3)');
        }

        return $value;
    }

}
