<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jws\Internal\B64Header;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;

/**
 * Pure structural serializer for the JWS JSON Serializations (RFC 7515
 * §7.2), both general ({@see GeneralJws}) and flattened ({@see FlattenedJws}).
 * The JSON counterpart to {@see CompactSerializer}.
 *
 * Has no knowledge of keys or crypto: turns a shared payload plus one or
 * more (protected header, unprotected header, signature) triples into a
 * JSON object and back into a {@see ParsedJsonJws}. The signing sits on
 * top in {@see Signer}; verification stays in {@see Verifier} — each
 * signature in the parsed result is a self-contained {@see ParsedJws}
 * that the existing single-signature `verify()` accepts as-is.
 *
 * What the JSON serialization adds over compact, and what this class
 * enforces:
 *
 *   - **Multiple signatures.** A general JWS may carry N signatures over
 *     the same payload (e.g. RS256 and ES256, for two recipients). Each
 *     signature has its own `protected` and `header`; the `payload` member
 *     is shared at the top level.
 *   - **Unprotected per-signature header.** Each signature may carry a
 *     `header` JSON object alongside its `protected` segment. Member
 *     names of `protected` and `header` MUST be disjoint per signature
 *     (RFC 7515 §7.2.1) — a parameter appearing in both is refused
 *     rather than silently resolved.
 *   - **Detached payload.** When the `payload` member is omitted, the
 *     JWS is detached (RFC 7515 Appendix F); the parsed result carries
 *     an empty payload and consumers must deliver the external bytes to
 *     {@see Verifier::verifyDetached()}.
 *   - **`b64:false` (RFC 7797 §5.2).** In a multi-signature JWS the `b64`
 *     value MUST be the same across all signatures (since the `payload`
 *     member is shared). Producers must keep them in sync; the parser
 *     refuses a JWS that mixes `b64:true` and `b64:false`.
 */
final class JsonSerializer
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * Assemble the flattened JSON serialization for a single signature.
     *
     * @param array<string, mixed> $protectedHeader   integrity-protected header for the signature
     * @param array<string, mixed> $unprotectedHeader the per-signature `header` (not authenticated)
     * @param string               $payload           raw payload bytes; pass `''` for the detached form
     * @param string               $signature         raw signature bytes
     *
     * @throws InvalidHeaderException
     * @throws MalformedJwtException
     */
    public static function serializeFlattened(
        array $protectedHeader,
        array $unprotectedHeader,
        string $payload,
        string $signature,
        bool $detached = false,
    ): FlattenedJws {
        B64Header::assertValid($protectedHeader);
        self::assertDisjoint($protectedHeader, $unprotectedHeader);

        $object = self::payloadMember($payload, $protectedHeader, $detached);
        $object += self::signatureMembers($protectedHeader, $unprotectedHeader, $signature);

        return new FlattenedJws(Json::encode($object));
    }

    /**
     * Assemble the general JSON serialization for one or more signatures.
     *
     * @param non-empty-list<array{protectedHeader: array<string, mixed>, unprotectedHeader: array<string, mixed>, signature: string}> $signatures
     *        the inputs for each signature row; `signature` is the raw signature bytes
     * @param string $payload raw payload bytes; pass `''` for the detached form
     *
     * @throws InvalidHeaderException
     * @throws MalformedJwtException
     */
    public static function serializeGeneral(
        array $signatures,
        string $payload,
        bool $detached = false,
    ): GeneralJws {
        self::assertB64AgreementAcrossSignatures(array_column($signatures, 'protectedHeader'));

        // Use the first signature's protected header to drive the payload
        // encoding; the b64-agreement check above guarantees they all
        // resolve to the same encoding choice.
        $referenceHeader = $signatures[0]['protectedHeader'];
        $object = self::payloadMember($payload, $referenceHeader, $detached);

        $rows = [];
        foreach ($signatures as $row) {
            B64Header::assertValid($row['protectedHeader']);
            self::assertDisjoint($row['protectedHeader'], $row['unprotectedHeader']);
            $rows[] = self::signatureMembers($row['protectedHeader'], $row['unprotectedHeader'], $row['signature']);
        }
        $object['signatures'] = $rows;

        return new GeneralJws(Json::encode($object));
    }

    /**
     * Decode a flattened or general JSON JWS into one {@see ParsedJsonJws}.
     * No crypto runs.
     *
     * Refusals at this stage:
     *   - Not a JSON object, duplicate top-level keys, or non-UTF-8 →
     *     {@see MalformedJwtException} (via {@see Json::decode()}).
     *   - Missing `signature` (flattened) or empty `signatures` (general) →
     *     {@see MalformedJwtException}.
     *   - A JWS that mixes the general `signatures` array with the flattened
     *     top-level `protected`/`header`/`signature` members →
     *     {@see MalformedJwtException}.
     *   - Per-signature header names overlapping with each other →
     *     {@see InvalidHeaderException} (RFC 7515 §7.2.1).
     *   - Per-signature protected header that fails the RFC 7797 + §4.1.11
     *     `b64`/`crit` rules → {@see InvalidHeaderException}.
     *   - Multi-signature JWS where the `b64` value disagrees across
     *     signatures → {@see InvalidHeaderException} (RFC 7797 §5.2).
     *
     * @throws MalformedJwtException
     * @throws InvalidHeaderException
     */
    public static function deserialize(string $json): ParsedJsonJws
    {
        $object = Json::decode($json);

        $signatureObjects = self::extractSignatures($object);
        $protectedHeaders = [];
        $parsed = [];

        foreach ($signatureObjects as $i => $sig) {
            $encodedProtected = self::readOptionalString($sig, 'protected', 'protected header (signature ' . $i . ')');
            $protectedHeader = [];
            if ($encodedProtected !== '') {
                $protectedHeader = Json::decode(self::decode($encodedProtected, 'protected header (signature ' . $i . ')'));
            }
            $unprotectedHeader = self::readObjectMember($sig, 'header', 'unprotected header (signature ' . $i . ')');
            $encodedSignature = self::readRequiredString($sig, 'signature', 'signature (signature ' . $i . ')');

            B64Header::assertValid($protectedHeader);
            self::assertDisjoint($protectedHeader, $unprotectedHeader);

            $protectedHeaders[] = $protectedHeader;

            $effectiveHeader = array_merge($protectedHeader, $unprotectedHeader);

            // Each parsed signature is a single-sig view: header is the
            // *effective* JOSE header (protected + unprotected), but the
            // signing-input bytes are reconstructed from the protected
            // header bytes on the wire, so the Verifier path is identical
            // to the compact one.
            $parsed[] = new ParsedJws(
                $encodedProtected,
                '', // filled in after we resolve the shared payload below
                $encodedSignature,
                $effectiveHeader,
                '', // raw payload also filled in below
                self::decode($encodedSignature, 'signature (signature ' . $i . ')'),
            );
        }

        // `$signatureObjects` from extractSignatures() is statically a
        // non-empty list (the JSON-shape refusal happens there), so the
        // matching `$parsed` list is also non-empty by construction.
        self::assertB64AgreementAcrossSignatures($protectedHeaders);

        [$payloadRaw, $encodedPayload] = self::resolvePayload($object, $protectedHeaders[0]);

        // Refill the payload-bearing fields on each ParsedJws.
        $rebuiltSignatures = [];
        foreach ($parsed as $sig) {
            $rebuiltSignatures[] = new ParsedJws(
                $sig->encodedHeader,
                $encodedPayload,
                $sig->encodedSignature,
                $sig->header,
                $payloadRaw,
                $sig->signature,
            );
        }

        return new ParsedJsonJws($payloadRaw, $rebuiltSignatures);
    }

    /**
     * Resolve the list of signature objects from either the general
     * `signatures` array or the flattened top-level fields.
     *
     * @param array<string, mixed> $object
     *
     * @return non-empty-list<array<string, mixed>>
     *
     * @throws MalformedJwtException
     */
    private static function extractSignatures(array $object): array
    {
        $hasFlattenedFields = array_key_exists('protected', $object)
            || array_key_exists('header', $object)
            || array_key_exists('signature', $object);
        $hasGeneralArray = array_key_exists('signatures', $object);

        if ($hasGeneralArray && $hasFlattenedFields) {
            throw new MalformedJwtException('JWS JSON object mixes the general "signatures" array with the flattened "protected"/"header"/"signature" members');
        }

        if ($hasGeneralArray) {
            $signatures = $object['signatures'];
            if (!is_array($signatures) || !array_is_list($signatures) || $signatures === []) {
                throw new MalformedJwtException('JWS JSON "signatures" must be a non-empty array');
            }
            foreach ($signatures as $row) {
                if (!self::isObject($row)) {
                    throw new MalformedJwtException('JWS JSON "signatures" entries must each be a JSON object');
                }
            }

            /** @var non-empty-list<array<string, mixed>> $signatures */
            return $signatures;
        }

        return [[
            'protected' => $object['protected'] ?? null,
            'header' => $object['header'] ?? null,
            'signature' => $object['signature'] ?? null,
        ]];
    }

    /**
     * Resolve the shared payload. When the `payload` member is absent the
     * JWS is detached (RFC 7515 Appendix F); the raw payload is `''` and
     * the encoded form is also `''`, so the reconstructed signing input
     * is `<protected>.` — recipients must deliver the external bytes via
     * {@see Verifier::verifyDetached()}.
     *
     * @param array<string, mixed> $object
     * @param array<string, mixed> $referenceProtectedHeader
     *
     * @return array{0: string, 1: string} [rawPayload, encodedPayload]
     *
     * @throws MalformedJwtException
     */
    private static function resolvePayload(array $object, array $referenceProtectedHeader): array
    {
        if (!array_key_exists('payload', $object)) {
            return ['', ''];
        }
        $value = $object['payload'];
        if (!is_string($value)) {
            throw new MalformedJwtException('JWS JSON "payload" must be a string');
        }

        $b64 = $referenceProtectedHeader['b64'] ?? null;
        if ($b64 === false) {
            // RFC 7797 §4.2: in JSON form the `payload` member is the raw
            // unencoded bytes when b64 is false.
            return [$value, $value];
        }

        return [self::decode($value, 'payload'), $value];
    }

    /**
     * @param array<string, mixed> $protectedHeader
     *
     * @return array{payload?: string}
     */
    private static function payloadMember(string $payload, array $protectedHeader, bool $detached): array
    {
        if ($detached) {
            return [];
        }
        $b64 = $protectedHeader['b64'] ?? null;
        $value = $b64 === false ? $payload : Base64Url::encode($payload);

        return ['payload' => $value];
    }

    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $unprotectedHeader
     *
     * @return array<string, mixed>
     */
    private static function signatureMembers(array $protectedHeader, array $unprotectedHeader, string $signature): array
    {
        $out = [];
        if ($protectedHeader !== []) {
            $out['protected'] = Base64Url::encode(Json::encode($protectedHeader));
        }
        if ($unprotectedHeader !== []) {
            $out['header'] = $unprotectedHeader;
        }
        $out['signature'] = Base64Url::encode($signature);

        return $out;
    }

    /**
     * @param array<string, mixed> $protected
     * @param array<string, mixed> $unprotected
     *
     * @throws InvalidHeaderException
     */
    private static function assertDisjoint(array $protected, array $unprotected): void
    {
        $collision = array_intersect_key($protected, $unprotected);
        if ($collision !== []) {
            throw new InvalidHeaderException(sprintf('JWS JSON per-signature protected and unprotected header parameter names must be disjoint (RFC 7515 §7.2.1); "%s" appears in both', array_key_first($collision)));
        }
    }

    /**
     * RFC 7797 §5.2: when a JWS JSON carries multiple signatures, the `b64`
     * value MUST be the same across all of them. Otherwise the shared
     * `payload` member cannot represent both encodings.
     *
     * @param list<array<string, mixed>> $protectedHeaders
     *
     * @throws InvalidHeaderException
     */
    private static function assertB64AgreementAcrossSignatures(array $protectedHeaders): void
    {
        if (count($protectedHeaders) <= 1) {
            return;
        }
        $first = $protectedHeaders[0]['b64'] ?? null;
        foreach ($protectedHeaders as $i => $header) {
            $b64 = $header['b64'] ?? null;
            if ($b64 !== $first) {
                throw new InvalidHeaderException(sprintf('JWS JSON signatures must all agree on "b64" (RFC 7797 §5.2); signature 0 has %s and signature %d has %s', self::describe($first), $i, self::describe($b64)));
            }
        }
    }

    /**
     * @param array<string, mixed> $object
     *
     * @throws MalformedJwtException
     */
    private static function readOptionalString(array $object, string $key, string $label): string
    {
        if (!array_key_exists($key, $object) || $object[$key] === null) {
            return '';
        }
        $value = $object[$key];
        if (!is_string($value)) {
            throw new MalformedJwtException(sprintf('JWS JSON "%s" (%s) must be a string when present', $key, $label));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $object
     *
     * @throws MalformedJwtException
     */
    private static function readRequiredString(array $object, string $key, string $label): string
    {
        if (!array_key_exists($key, $object) || $object[$key] === null) {
            throw new MalformedJwtException(sprintf('JWS JSON "%s" (%s) is required', $key, $label));
        }
        $value = $object[$key];
        if (!is_string($value) || $value === '') {
            throw new MalformedJwtException(sprintf('JWS JSON "%s" (%s) must be a non-empty string', $key, $label));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $object
     *
     * @return array<string, mixed>
     *
     * @throws MalformedJwtException
     */
    private static function readObjectMember(array $object, string $key, string $label): array
    {
        if (!array_key_exists($key, $object) || $object[$key] === null) {
            return [];
        }
        $value = $object[$key];
        if (!self::isObject($value)) {
            throw new MalformedJwtException(sprintf('JWS JSON "%s" (%s) must be a JSON object', $key, $label));
        }

        return $value;
    }

    /**
     * @phpstan-assert-if-true array<string, mixed> $value
     */
    private static function isObject(mixed $value): bool
    {
        // An empty PHP array can stand in for an empty JSON object — our
        // Json::decode is configured to return associative arrays. A
        // *list*-shaped array is the one case we must refuse here, since
        // it would have decoded from a JSON array, not an object.
        return is_array($value) && ($value === [] || !array_is_list($value));
    }

    /**
     * @throws MalformedJwtException
     */
    private static function decode(string $encoded, string $label): string
    {
        try {
            return Base64Url::decode($encoded);
        } catch (\Throwable $e) {
            throw new MalformedJwtException(sprintf('JWS JSON %s is not valid base64url', $label), 0, $e);
        }
    }

    private static function describe(mixed $value): string
    {
        return match (true) {
            $value === null => 'absent',
            $value === true => 'true',
            $value === false => 'false',
            default => '(' . get_debug_type($value) . ')',
        };
    }
}
