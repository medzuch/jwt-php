<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;

/**
 * Pure structural serializer for the JWE Compact Serialization
 * (RFC 7516 §7.1). The JWE counterpart to {@see \Medzuch\Jwt\Jws\CompactSerializer}.
 *
 * Has no knowledge of keys, algorithms, or claims. Its only job is to turn
 * `(header, encryptedKey, iv, ciphertext, tag)` into the canonical
 * five-segment dotted string and back. {@see Encrypter} and {@see Decrypter}
 * add the crypto on top.
 *
 * Splitting this out keeps the crypto layer unit-testable without real keys
 * and gives the JWT layer a header-before-crypto inspection point for its
 * two-phase parse (it must read `alg`/`enc`/`kid`/`epk` before resolving a
 * key and decrypting).
 */
final class CompactSerializer
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * Encode `(header, encryptedKey, iv, ciphertext, tag)` as a compact JWE.
     *
     * @param array<string, mixed> $header protected header
     * @param string $encryptedKey raw JWE Encrypted Key bytes (empty for
     *                             `dir` / ECDH-ES direct key agreement)
     * @param string $iv           raw initialization vector bytes
     * @param string $ciphertext   raw ciphertext bytes
     * @param string $tag          raw authentication tag bytes
     *
     * @throws MalformedJwtException on JSON-encode failure
     */
    public static function serialize(array $header, string $encryptedKey, string $iv, string $ciphertext, string $tag): CompactJwe
    {
        return new CompactJwe(implode('.', [
            Base64Url::encode(Json::encode($header)),
            Base64Url::encode($encryptedKey),
            Base64Url::encode($iv),
            Base64Url::encode($ciphertext),
            Base64Url::encode($tag),
        ]));
    }

    /**
     * Decode a compact JWE string into its constituent pieces and the parsed
     * protected header. No crypto runs.
     *
     * Refusals at this stage:
     *   - Wrong number of `.`-separated segments → {@see MalformedJwtException}.
     *   - Any segment not valid base64url → {@see MalformedJwtException}.
     *   - Empty header, IV, or tag segment → {@see MalformedJwtException}. The
     *     Encrypted Key and ciphertext segments MAY be empty (`dir`/ECDH-ES
     *     ship no Encrypted Key; an empty plaintext yields empty ciphertext),
     *     but every JWE this library handles has an IV and an authentication
     *     tag.
     *   - Header not a JSON object → {@see MalformedJwtException}.
     *   - Header missing `alg` or `enc`, or either not a non-empty string →
     *     {@see InvalidHeaderException} (a JWE MUST carry both, RFC 7516 §4.1).
     *   - Header declares `crit` or `zip` → {@see InvalidHeaderException}: this
     *     library understands no `crit` extensions (RFC 7516 §4.1.13 requires
     *     refusal) and refuses JWE compression by default (RFC 8725 §3.6).
     *
     * @throws MalformedJwtException
     * @throws InvalidHeaderException
     */
    public static function deserialize(string $compact): ParsedJwe
    {
        if ($compact === '') {
            throw new MalformedJwtException('Compact JWE is empty');
        }

        $segments = explode('.', $compact);
        if (count($segments) !== 5) {
            throw new MalformedJwtException(sprintf('Compact JWE must have exactly 5 dot-separated segments; got %d', count($segments)));
        }

        [$encodedHeader, $encodedEncryptedKey, $encodedIv, $encodedCiphertext, $encodedTag] = $segments;

        if ($encodedHeader === '') {
            throw new MalformedJwtException('Compact JWE protected header segment is empty');
        }
        if ($encodedIv === '') {
            throw new MalformedJwtException('Compact JWE initialization vector segment is empty');
        }
        if ($encodedTag === '') {
            throw new MalformedJwtException('Compact JWE authentication tag segment is empty');
        }

        $header = Json::decode(Base64Url::decode($encodedHeader));

        self::assertHeaderShape($header);

        return new ParsedJwe(
            $encodedHeader,
            $encodedEncryptedKey,
            $encodedIv,
            $encodedCiphertext,
            $encodedTag,
            $header,
            Base64Url::decode($encodedEncryptedKey),
            Base64Url::decode($encodedIv),
            Base64Url::decode($encodedCiphertext),
            Base64Url::decode($encodedTag),
        );
    }

    /**
     * @param array<string, mixed> $header
     *
     * @throws InvalidHeaderException
     */
    private static function assertHeaderShape(array $header): void
    {
        foreach (['alg', 'enc'] as $required) {
            if (!array_key_exists($required, $header)) {
                throw new InvalidHeaderException(sprintf('JWE protected header is missing required "%s"', $required));
            }
            if (!is_string($header[$required]) || $header[$required] === '') {
                throw new InvalidHeaderException(sprintf('JWE protected header "%s" must be a non-empty string', $required));
            }
        }

        // `array_key_exists`, not `isset`: a header that declares one of these
        // with an explicit JSON `null` must be refused too, not treated as
        // absent (RFC 7516 §4).
        if (array_key_exists('crit', $header)) {
            throw new InvalidHeaderException('JWE protected header declares "crit" extensions; this library understands none and RFC 7516 §4.1.13 requires refusal');
        }
        if (array_key_exists('zip', $header)) {
            throw new InvalidHeaderException('JWE protected header declares "zip"; compression is refused by default (RFC 8725 §3.6)');
        }

        foreach (['typ', 'cty', 'kid'] as $optionalString) {
            if (array_key_exists($optionalString, $header) && !is_string($header[$optionalString])) {
                throw new InvalidHeaderException(sprintf('JWE protected header "%s" must be a string when present', $optionalString));
            }
        }
    }
}
