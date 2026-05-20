<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use RuntimeException;

/**
 * The JOSE header is structurally valid but semantically unacceptable.
 *
 * For example: missing `alg`, `b64:false` in a JWT (RFC 7797 §7),
 * `crit` referencing unsupported extensions.
 */
final class InvalidHeaderException extends RuntimeException implements JwtException
{
}
