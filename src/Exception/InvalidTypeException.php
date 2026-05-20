<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * `typ` header did not match the profile's required media type.
 *
 * Declared in Phase 1; thrown starting Phase 2 when `typ` enforcement lands.
 * RFC 8725 §3.11.
 */
final class InvalidTypeException extends ClaimValidationException
{
}
