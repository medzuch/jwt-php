<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * `aud` did not contain the validator's expected audience value.
 *
 * Comparison is case-sensitive per RFC 7519 §4.1.3.
 */
final class InvalidAudienceException extends ClaimValidationException {}
