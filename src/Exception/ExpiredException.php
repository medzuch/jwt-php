<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * `exp` claim is in the past (now ≥ exp), accounting for any configured leeway.
 *
 * RFC 7519 §4.1.4.
 */
final class ExpiredException extends ClaimValidationException
{
}
