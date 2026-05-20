<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\KeyNotFoundException;

/**
 * Strategy for "given a JWS/JWT header, what key should verify it?".
 *
 * Implementations may consult a local JWK Set, a remote `jwks_uri`
 * (Phase 2), a database, etc. The header value passed in is the parsed,
 * already-validated protected header — never re-decode from raw bytes
 * inside a resolver.
 *
 * `jku` and `x5u` are **never** followed by default; opt-in resolvers
 * that consult them must require an explicit URL allowlist
 * (RFC 8725 §3.10, threat T11).
 */
interface KeyResolver
{
    /**
     * @param array<string, mixed> $header parsed JOSE header
     *
     * @throws KeyNotFoundException
     */
    public function resolve(array $header): Key;
}
