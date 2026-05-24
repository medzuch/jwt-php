<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

/**
 * Structural parse of a compact JWS — three encoded segments plus the
 * decoded protected header. Crypto has NOT been verified yet.
 *
 * Two-phase JWS/JWT consumption needs an intermediate value: the JWT API
 * layer (PR #5) wants to look at `kid` before deciding which key set to
 * resolve against, and a multi-tenant caller wants the same for tenant
 * dispatch. Exposing the parse step as its own value object is the only
 * way to make that inspection a first-class API instead of forcing the
 * caller to base64url-decode the header themselves (which would defeat
 * the safety the library provides).
 *
 * Fields:
 *   - `encodedHeader`, `encodedPayload`, `encodedSignature` — the three
 *     base64url segments, as bytes, exactly as received.
 *   - `header` — the decoded JSON object of the protected header.
 *   - `payload` — the raw decoded payload bytes (whether they happen to
 *     be JSON is the JWT layer's concern, not the JWS layer's).
 *   - `signature` — the raw decoded signature bytes.
 *
 * `signingInput()` reconstructs the exact bytes that were signed, per
 * RFC 7515 §5.1: `ASCII(encodedHeader || "." || encodedPayload)`.
 */
final readonly class ParsedJws
{
    /** @param array<string, mixed> $header */
    public function __construct(
        public string $encodedHeader,
        public string $encodedPayload,
        public string $encodedSignature,
        public array $header,
        public string $payload,
        public string $signature,
    ) {}

    public function signingInput(): string
    {
        return $this->encodedHeader . '.' . $this->encodedPayload;
    }
}
