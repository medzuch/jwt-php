<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use LogicException;

/**
 * Structural parse of a JWS JSON Serialization (RFC 7515 §7.2) — the shared
 * payload plus one {@see ParsedJws} per signature. Crypto has NOT been
 * verified yet.
 *
 * Each `$signatures[i]` is self-contained: its `encodedHeader` is that
 * signature's own `protected` member, the `encodedPayload` is the shared
 * top-level `payload` (so `signingInput()` is the right bytes), and
 * `signature` is that signature's bytes. The caller hands each entry to
 * the existing {@see Verifier::verify()} as-is — no JSON-specific verify
 * path is needed.
 *
 * Verification policy is the caller's call: "accept if any signature
 * verifies under a trusted key", "accept only if all do", "require a
 * signature with a specific `kid`". The library does not pick one for them
 * — that's an application-level decision and depends on what the
 * recipient is trying to assure.
 */
final readonly class ParsedJsonJws
{
    /**
     * @param string                $payload    raw payload bytes (empty for a detached JWS)
     * @param non-empty-list<ParsedJws> $signatures one ParsedJws per signature
     */
    public function __construct(
        public string $payload,
        public array $signatures,
    ) {}

    /**
     * Convenience for the flattened case (or a general JWS that happens to
     * carry only one signature): return the sole `ParsedJws`, or throw if
     * the JWS carries more.
     */
    public function single(): ParsedJws
    {
        if (count($this->signatures) !== 1) {
            throw new LogicException(sprintf('ParsedJsonJws::single() called on a JWS with %d signatures', count($this->signatures)));
        }

        return $this->signatures[0];
    }
}
