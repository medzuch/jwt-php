<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

/**
 * Result of {@see NestedJwtParser::parse()} — a JWE that wraps a JWS that
 * carries a JWT Claims Set (RFC 7519 §5.2 nested JWT).
 *
 * Successful construction implies: the outer JWE decrypted (content tag
 * authenticated the protected header bytes), the inner JWS signature
 * verified under an allowlisted algorithm, the outer header declares
 * `cty: JWT` (RFC 7519 §5.2), and any claim names present in both the
 * outer header and the inner Claims Set hold equal values (RFC 7519 §5.3).
 *
 * `outerHeader` is the *effective* JOSE header of the outer JWE — the union
 * of the protected, shared-unprotected, and per-recipient unprotected
 * headers for a JSON-serialised JWE, or just the protected header for the
 * compact form. Only the protected header was actually integrity-covered;
 * downstream code that routes on a replicated `iss` / `kid` / similar from
 * here should keep that in mind (T16 in `docs/02-threat-model.md`).
 */
final readonly class NestedJwt
{
    /** @param array<string, mixed> $outerHeader */
    public function __construct(
        public array $outerHeader,
        public ParsedJwt $inner,
    ) {}
}
