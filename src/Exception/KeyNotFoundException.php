<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use RuntimeException;

/**
 * No key matched the JOSE header (e.g. `kid` not present in the JWK set).
 */
final class KeyNotFoundException extends RuntimeException implements JwtException
{
}
