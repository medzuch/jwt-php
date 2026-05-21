<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * `iss` did not match the validator's expected issuer.
 *
 * Comparison is case-sensitive per RFC 7519 §4.1.1.
 */
final class InvalidIssuerException extends ClaimValidationException {}
