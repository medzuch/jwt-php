<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe;

/**
 * Structural parse of a compact JWE — five encoded segments plus the decoded
 * protected header. Nothing has been decrypted or authenticated yet.
 *
 * The JWE counterpart to {@see \Medzuch\Jwt\Jws\ParsedJws}. Two-phase
 * consumption needs it for the same reason: a recipient wants to read `kid`
 * (and, for ECDH-ES, `epk`/`alg`/`enc`) before choosing a key, and exposing
 * the parse step as a value object keeps that inspection a first-class API
 * instead of forcing callers to base64url-decode the header by hand.
 *
 * Fields:
 *   - `encodedHeader`, `encodedEncryptedKey`, `encodedIv`,
 *     `encodedCiphertext`, `encodedTag` — the five base64url segments, as
 *     bytes, exactly as received.
 *   - `header` — the decoded JSON object of the JWE Protected Header.
 *   - `encryptedKey` — raw JWE Encrypted Key bytes (empty for `dir` and
 *     ECDH-ES direct key agreement).
 *   - `iv`, `ciphertext`, `tag` — raw decoded content-encryption bytes.
 *
 * `additionalAuthenticatedData()` returns the exact octets the content
 * algorithm authenticates, per RFC 7516 §5.1 step 14: for the compact
 * serialization that is `ASCII(BASE64URL(UTF8(Protected Header)))`, i.e. the
 * header segment as received — never re-encoded, so a recipient authenticates
 * the bytes on the wire rather than a canonicalised copy.
 */
final readonly class ParsedJwe
{
    /** @param array<string, mixed> $header */
    public function __construct(
        public string $encodedHeader,
        public string $encodedEncryptedKey,
        public string $encodedIv,
        public string $encodedCiphertext,
        public string $encodedTag,
        public array $header,
        public string $encryptedKey,
        public string $iv,
        public string $ciphertext,
        public string $tag,
    ) {}

    public function additionalAuthenticatedData(): string
    {
        return $this->encodedHeader;
    }
}
