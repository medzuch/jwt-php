<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jwe\Internal\JweHeader;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;

/**
 * Pure structural serializer for the JWE JSON Serialization (RFC 7516 §7.2),
 * both the general ({@see GeneralJwe}) and flattened ({@see FlattenedJwe})
 * syntaxes. The JSON counterpart to {@see CompactSerializer}.
 *
 * Like its compact sibling it has no knowledge of keys, algorithms, or claims:
 * it turns the content-encryption pieces plus the three header sources
 * (protected, shared-unprotected, per-recipient unprotected) into a JSON object
 * and back into a {@see ParsedJwe}. The crypto sits on top in {@see Encrypter}
 * and {@see Decrypter}.
 *
 * What the JSON serialization adds over compact, and what this class enforces:
 *
 *   - **Unprotected headers.** Header parameters may live outside the
 *     integrity-protected `protected` member (in `unprotected` or a recipient's
 *     `header`). Only the `protected` member feeds the AAD; the effective JOSE
 *     header a recipient acts on is the union of all three. Their member names
 *     MUST be pairwise disjoint (§7.2.1) — a parameter appearing twice is
 *     refused rather than silently resolved.
 *   - **`aad`.** An explicit Additional Authenticated Data member, folded into
 *     the AAD as `Encoded Protected Header || '.' || BASE64URL(JWE AAD)`.
 *   - **Absent protected header.** A JWE may carry no protected header at all
 *     (`protected` omitted), provided `alg`/`enc` arrive via an unprotected
 *     header; the AAD is then computed over the empty string.
 *
 * Multiple recipients (a `recipients` array longer than one) are not yet
 * supported and are refused on parse; production emits a single recipient.
 */
final class JsonSerializer
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * Assemble the flattened JSON serialization for a single recipient.
     *
     * @param array<string, mixed> $protectedHeader   integrity-protected header (drives the AAD)
     * @param array<string, mixed> $sharedUnprotected `unprotected` shared header (not authenticated)
     * @param array<string, mixed> $recipientHeader   the recipient's `header` (not authenticated)
     * @param string               $encryptedKey      raw JWE Encrypted Key bytes (empty for `dir`/ECDH-ES direct)
     * @param string               $iv                raw initialization vector bytes
     * @param string               $ciphertext        raw ciphertext bytes
     * @param string               $tag               raw authentication tag bytes
     * @param ?string              $aad               raw JWE AAD bytes, or null when absent
     *
     * @throws InvalidHeaderException if the three header sources share a member name
     * @throws MalformedJwtException  on JSON-encode failure
     */
    public static function serializeFlattened(
        array $protectedHeader,
        array $sharedUnprotected,
        array $recipientHeader,
        string $encryptedKey,
        string $iv,
        string $ciphertext,
        string $tag,
        ?string $aad = null,
    ): FlattenedJwe {
        self::assertDisjoint($protectedHeader, $sharedUnprotected, $recipientHeader);

        $object = self::commonMembers($protectedHeader, $sharedUnprotected, $iv, $ciphertext, $tag, $aad);
        if ($recipientHeader !== []) {
            $object['header'] = $recipientHeader;
        }
        if ($encryptedKey !== '') {
            $object['encrypted_key'] = Base64Url::encode($encryptedKey);
        }

        return new FlattenedJwe(Json::encode($object));
    }

    /**
     * Assemble the general JSON serialization for a single recipient (emitted in
     * the canonical `recipients`-array shape).
     *
     * @param array<string, mixed> $protectedHeader   integrity-protected header (drives the AAD)
     * @param array<string, mixed> $sharedUnprotected `unprotected` shared header (not authenticated)
     * @param array<string, mixed> $recipientHeader   the recipient's `header` (not authenticated)
     * @param string               $encryptedKey      raw JWE Encrypted Key bytes (empty for `dir`/ECDH-ES direct)
     * @param string               $iv                raw initialization vector bytes
     * @param string               $ciphertext        raw ciphertext bytes
     * @param string               $tag               raw authentication tag bytes
     * @param ?string              $aad               raw JWE AAD bytes, or null when absent
     *
     * @throws InvalidHeaderException if the three header sources share a member name
     * @throws MalformedJwtException  on JSON-encode failure
     */
    public static function serializeGeneral(
        array $protectedHeader,
        array $sharedUnprotected,
        array $recipientHeader,
        string $encryptedKey,
        string $iv,
        string $ciphertext,
        string $tag,
        ?string $aad = null,
    ): GeneralJwe {
        self::assertDisjoint($protectedHeader, $sharedUnprotected, $recipientHeader);

        $recipient = [];
        if ($recipientHeader !== []) {
            $recipient['header'] = $recipientHeader;
        }
        if ($encryptedKey !== '') {
            $recipient['encrypted_key'] = Base64Url::encode($encryptedKey);
        }

        $object = self::commonMembers($protectedHeader, $sharedUnprotected, $iv, $ciphertext, $tag, $aad);
        // A recipient with neither member is still a JSON *object*, not the
        // empty array `[]` json_encode would otherwise emit.
        $object['recipients'] = [$recipient === [] ? (object) [] : $recipient];

        return new GeneralJwe(Json::encode($object));
    }

    /**
     * Decode a flattened or general JSON JWE into one {@see ParsedJwe}. No
     * crypto runs.
     *
     * Refusals at this stage:
     *   - Not a JSON object, duplicate top-level keys, or non-UTF-8 →
     *     {@see MalformedJwtException} (via {@see Json::decode()}).
     *   - Missing `ciphertext`, `iv`, or `tag`, or any of the typed members the
     *     wrong JSON type → {@see MalformedJwtException}.
     *   - A `recipients` array that is empty, not an array, or carries more than
     *     one recipient → {@see MalformedJwtException} (multi-recipient is not
     *     supported in this version).
     *   - A JWE that mixes the general `recipients` array with the flattened
     *     top-level `header`/`encrypted_key` → {@see MalformedJwtException}.
     *   - Header parameter names shared across the protected, shared, and
     *     per-recipient headers → {@see InvalidHeaderException} (§7.2.1).
     *   - An effective header missing `alg`/`enc` or declaring `crit`/`zip`/`b64`
     *     → {@see InvalidHeaderException} (via {@see JweHeader::assertShape()}),
     *     the same fail-closed checks the compact serializer applies.
     *
     * @throws MalformedJwtException
     * @throws InvalidHeaderException
     */
    public static function deserialize(string $json): ParsedJwe
    {
        $object = Json::decode($json);

        [$recipientHeader, $encodedEncryptedKey] = self::extractRecipient($object);

        $encodedProtected = self::readOptionalString($object, 'protected', 'protected header');
        $protectedHeader = [];
        if ($encodedProtected !== '') {
            $protectedHeader = Json::decode(self::decode($encodedProtected, 'protected header'));
        }

        $sharedUnprotected = self::readObjectMember($object, 'unprotected', 'unprotected header');

        $encodedIv = self::readRequiredString($object, 'iv', 'initialization vector');
        $encodedCiphertext = self::readRequiredString($object, 'ciphertext', 'ciphertext', allowEmpty: true);
        $encodedTag = self::readRequiredString($object, 'tag', 'authentication tag');

        $encodedAad = null;
        if (array_key_exists('aad', $object)) {
            $encodedAad = self::readRequiredString($object, 'aad', 'additional authenticated data');
            // The encoded form is what feeds the AAD, but it must still be valid
            // base64url — reject a malformed one here rather than let it surface
            // as an opaque tag mismatch.
            self::decode($encodedAad, 'additional authenticated data');
        }

        self::assertDisjoint($protectedHeader, $sharedUnprotected, $recipientHeader);

        $header = array_merge($protectedHeader, $sharedUnprotected, $recipientHeader);
        JweHeader::assertShape($header);

        return new ParsedJwe(
            $encodedProtected,
            $encodedEncryptedKey,
            $encodedIv,
            $encodedCiphertext,
            $encodedTag,
            $header,
            self::decode($encodedEncryptedKey, 'encrypted key'),
            self::decode($encodedIv, 'initialization vector'),
            self::decode($encodedCiphertext, 'ciphertext'),
            self::decode($encodedTag, 'authentication tag'),
            $encodedAad,
        );
    }

    /**
     * Resolve the single recipient's per-recipient header and encoded Encrypted
     * Key from either the general `recipients` array or the flattened top-level
     * members.
     *
     * @param array<string, mixed> $object
     *
     * @return array{0: array<string, mixed>, 1: string}
     *
     * @throws MalformedJwtException
     */
    private static function extractRecipient(array $object): array
    {
        if (!array_key_exists('recipients', $object)) {
            return [
                self::readObjectMember($object, 'header', 'header'),
                self::readOptionalString($object, 'encrypted_key', 'encrypted key'),
            ];
        }

        if (array_key_exists('header', $object) || array_key_exists('encrypted_key', $object)) {
            throw new MalformedJwtException('JWE JSON object mixes the general "recipients" array with the flattened "header"/"encrypted_key" members');
        }

        $recipients = $object['recipients'];
        if (!is_array($recipients) || !array_is_list($recipients) || $recipients === []) {
            throw new MalformedJwtException('JWE JSON "recipients" must be a non-empty array');
        }
        if (count($recipients) > 1) {
            throw new MalformedJwtException(sprintf('JWE JSON with multiple recipients (%d) is not supported in this version', count($recipients)));
        }

        $recipient = $recipients[0];
        if (!self::isObject($recipient)) {
            throw new MalformedJwtException('JWE JSON "recipients" entry must be a JSON object');
        }

        return [
            self::readObjectMember($recipient, 'header', 'recipient header'),
            self::readOptionalString($recipient, 'encrypted_key', 'recipient encrypted key'),
        ];
    }

    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $sharedUnprotected
     * @param ?string              $aad
     *
     * @return array<string, mixed>
     */
    private static function commonMembers(array $protectedHeader, array $sharedUnprotected, string $iv, string $ciphertext, string $tag, ?string $aad): array
    {
        $object = [];
        if ($protectedHeader !== []) {
            $object['protected'] = Base64Url::encode(Json::encode($protectedHeader));
        }
        if ($sharedUnprotected !== []) {
            $object['unprotected'] = $sharedUnprotected;
        }
        if ($aad !== null) {
            $object['aad'] = Base64Url::encode($aad);
        }
        $object['iv'] = Base64Url::encode($iv);
        $object['ciphertext'] = Base64Url::encode($ciphertext);
        $object['tag'] = Base64Url::encode($tag);

        return $object;
    }

    /**
     * @param array<string, mixed> $protected
     * @param array<string, mixed> $shared
     * @param array<string, mixed> $perRecipient
     *
     * @throws InvalidHeaderException
     */
    private static function assertDisjoint(array $protected, array $shared, array $perRecipient): void
    {
        /** @var list<array{string, array<string, mixed>, array<string, mixed>}> $pairs */
        $pairs = [
            ['protected and unprotected', $protected, $shared],
            ['protected and per-recipient', $protected, $perRecipient],
            ['unprotected and per-recipient', $shared, $perRecipient],
        ];

        foreach ($pairs as [$where, $a, $b]) {
            $collision = array_intersect_key($a, $b);
            if ($collision !== []) {
                throw new InvalidHeaderException(sprintf('JWE JSON header parameter names must be disjoint (RFC 7516 §7.2.1); "%s" appears in both the %s headers', array_key_first($collision), $where));
            }
        }
    }

    /**
     * A member that must be a string when present; absence yields the empty
     * string, which downstream treats as "omitted".
     *
     * @param array<string, mixed> $object
     *
     * @throws MalformedJwtException
     */
    private static function readOptionalString(array $object, string $key, string $label): string
    {
        if (!array_key_exists($key, $object)) {
            return '';
        }
        $value = $object[$key];
        if (!is_string($value)) {
            throw new MalformedJwtException(sprintf('JWE JSON "%s" (%s) must be a string', $key, $label));
        }

        return $value;
    }

    /**
     * A member that must be present and a string, optionally non-empty.
     *
     * @param array<string, mixed> $object
     *
     * @throws MalformedJwtException
     */
    private static function readRequiredString(array $object, string $key, string $label, bool $allowEmpty = false): string
    {
        if (!array_key_exists($key, $object)) {
            throw new MalformedJwtException(sprintf('JWE JSON is missing required "%s" (%s)', $key, $label));
        }
        $value = $object[$key];
        if (!is_string($value)) {
            throw new MalformedJwtException(sprintf('JWE JSON "%s" (%s) must be a string', $key, $label));
        }
        if (!$allowEmpty && $value === '') {
            throw new MalformedJwtException(sprintf('JWE JSON "%s" (%s) must not be empty', $key, $label));
        }

        return $value;
    }

    /**
     * A member that must be a JSON object when present; absence yields `[]`.
     *
     * @param array<string, mixed> $object
     *
     * @return array<string, mixed>
     *
     * @throws MalformedJwtException
     */
    private static function readObjectMember(array $object, string $key, string $label): array
    {
        if (!array_key_exists($key, $object)) {
            return [];
        }
        $value = $object[$key];
        if (!self::isObject($value)) {
            throw new MalformedJwtException(sprintf('JWE JSON "%s" (%s) must be a JSON object', $key, $label));
        }
        /** @var array<string, mixed> $value */

        return $value;
    }

    /**
     * Is `$value` a decoded JSON *object* — an associative array, or the empty
     * array that `json_decode` produces from `{}`? A non-empty list (a JSON
     * array) is not.
     *
     * @phpstan-assert-if-true array<string, mixed> $value
     */
    private static function isObject(mixed $value): bool
    {
        return is_array($value) && ($value === [] || !array_is_list($value));
    }

    /**
     * Base64url-decode one member, rethrowing with its name so a malformed token
     * tells the caller which part failed.
     *
     * @throws MalformedJwtException
     */
    private static function decode(string $encoded, string $label): string
    {
        try {
            return Base64Url::decode($encoded);
        } catch (MalformedJwtException $e) {
            throw new MalformedJwtException(sprintf('JWE JSON %s is not valid base64url', $label), 0, $e);
        }
    }
}
