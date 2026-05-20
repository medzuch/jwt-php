<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use RuntimeException;

/**
 * Key material is malformed, of the wrong shape, or fails policy.
 *
 * Examples: PEM that OpenSSL refuses, JWK missing a required parameter,
 * HMAC secret below the minimum entropy for its algorithm (RFC 8725 §3.5),
 * an EC point that is not on the named curve (Phase 2+).
 *
 * Distinct from KeyMismatchException, which is reserved for the case
 * where a syntactically-valid key is presented to the wrong algorithm.
 */
final class InvalidKeyException extends RuntimeException implements JwtException
{
}
