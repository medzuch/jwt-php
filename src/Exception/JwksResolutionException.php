<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use RuntimeException;

/**
 * A remote JWKS could not be turned into a usable key.
 *
 * Covers transport failures (the PSR-18 client threw), a non-200 response,
 * an over-sized body, or a document that is not a valid RFC 7517 JWK Set.
 * It is a {@see JwtException}, so a
 * {@see \Medzuch\Jwt\Key\Resolver\CompositeResolver} treats a flaky remote
 * endpoint the same as a plain miss — falling through to the next resolver
 * (e.g. a static set of still-valid rotation keys) rather than failing the
 * whole resolution.
 */
final class JwksResolutionException extends RuntimeException implements JwtException {}
