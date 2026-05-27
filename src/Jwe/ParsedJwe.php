<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe;

/**
 * Structural parse of one JWE recipient — the encoded pieces plus the effective
 * JOSE header. Nothing has been decrypted or authenticated yet. Produced by
 * {@see CompactSerializer::deserialize()} (one per compact token) and by
 * {@see JsonSerializer::deserialize()} (one per recipient of a JSON JWE).
 *
 * The JWE counterpart to {@see \Medzuch\Jwt\Jws\ParsedJws}. Two-phase
 * consumption needs it for the same reason: a recipient wants to read `kid`
 * (and, for ECDH-ES, `epk`/`alg`/`enc`) before choosing a key, and exposing
 * the parse step as a value object keeps that inspection a first-class API
 * instead of forcing callers to base64url-decode the header by hand.
 *
 * Fields:
 *   - `encodedHeader` — `BASE64URL(UTF8(Protected Header))` exactly as received,
 *     i.e. the bytes that feed the AAD. For the compact serialization this is
 *     the header segment; for the JSON serialization it is the `protected`
 *     member (the empty string when a JWE carries no protected header).
 *   - `encodedEncryptedKey`, `encodedIv`, `encodedCiphertext`, `encodedTag` —
 *     the base64url representations, as bytes, exactly as received.
 *   - `header` — the *effective* JOSE header this recipient acts on: for the
 *     compact serialization the decoded protected header; for the JSON
 *     serialization the union of the protected, shared-unprotected, and
 *     per-recipient unprotected headers (RFC 7516 §7.2.1).
 *   - `encryptedKey` — raw JWE Encrypted Key bytes (empty for `dir` and
 *     ECDH-ES direct key agreement).
 *   - `iv`, `ciphertext`, `tag` — raw decoded content-encryption bytes.
 *   - `aad` — `BASE64URL(JWE AAD)` exactly as received, or `null` when the JWE
 *     carries no `aad` member. Only the JSON serialization can supply it.
 *
 * `additionalAuthenticatedData()` returns the exact octets the content
 * algorithm authenticates, per RFC 7516 §5.1 step 14: `ASCII(Encoded Protected
 * Header)`, or — when a JWE AAD is present (JSON serialization only) —
 * `ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD))`. The header
 * bytes are never re-encoded, so a recipient authenticates the bytes on the
 * wire rather than a canonicalised copy.
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
        public ?string $aad = null,
    ) {}

    public function additionalAuthenticatedData(): string
    {
        return $this->aad === null
            ? $this->encodedHeader
            : $this->encodedHeader . '.' . $this->aad;
    }
}
