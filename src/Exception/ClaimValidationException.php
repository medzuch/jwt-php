<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use RuntimeException;

/**
 * Base class for semantic claim failures.
 *
 * Catch this to distinguish "the token was structurally valid and properly
 * signed, but its claims don't satisfy the validator's expectations" from
 * the lower-level malformed/crypto failures.
 */
abstract class ClaimValidationException extends RuntimeException implements JwtException {}
