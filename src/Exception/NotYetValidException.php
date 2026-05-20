<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * `nbf` claim is in the future (now < nbf), accounting for any configured leeway.
 *
 * RFC 7519 §4.1.5.
 */
final class NotYetValidException extends ClaimValidationException
{
}
