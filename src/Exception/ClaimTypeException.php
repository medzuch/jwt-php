<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * A typed claim accessor was called but the underlying value has the wrong shape.
 *
 * Thrown by ClaimsSet::getString(), getInt(), getList(), getBool() when the
 * stored JSON value does not match the requested type.
 */
final class ClaimTypeException extends ClaimValidationException
{
}
