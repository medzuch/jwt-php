<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use RuntimeException;

/**
 * Key type does not match the algorithm asking to use it.
 *
 * Load-bearing mitigation for the RS256→HS256 confusion attack
 * (RFC 8725 §3.1): an RSA public key cannot be coerced into an HMAC
 * secret because the HMAC algorithm refuses to accept it.
 */
final class KeyMismatchException extends RuntimeException implements JwtException
{
}
