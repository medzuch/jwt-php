<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Key\PrivateKey;

/**
 * One row in the input to {@see Signer::signGeneral()} — everything needed
 * to produce a single signature in a JSON-serialized JWS. Bundled as a
 * value object rather than a positional tuple so the call site is
 * self-documenting and PHPStan can narrow the types across the multi-
 * signature boundary.
 *
 * Fields:
 *   - `algorithm` — the strategy that signs (also fills in `alg`).
 *   - `protectedHeader` — the integrity-protected header for *this*
 *     signature; may carry `kid`, `typ`, etc. plus the RFC 7797 `b64`
 *     flag. Member names MUST be disjoint from `unprotectedHeader`.
 *   - `unprotectedHeader` — the per-signature unauthenticated header (the
 *     JSON `header` member of this signature). Empty by default.
 *   - `key` — the signing key, narrowed to the algorithm by the strategy.
 *
 * Each signature in a general JWS is independent of the others, with one
 * exception: RFC 7797 §5.2 requires all signatures in a multi-signature
 * JWS to agree on the `b64` mode (since the `payload` member is shared).
 * {@see Signer::signGeneral()} enforces that across the list.
 */
final readonly class SignatureSpec
{
    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $unprotectedHeader
     */
    public function __construct(
        public SigningAlgorithm $algorithm,
        public array $protectedHeader,
        public PrivateKey $key,
        public array $unprotectedHeader = [],
    ) {}
}
