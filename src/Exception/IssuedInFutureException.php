<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * `iat` is implausibly far in the future — a sanity guard against clock-skew abuse.
 *
 * RFC 7519 §4.1.6 makes `iat` informational; the validator treats absurd
 * future values as malformed-by-policy.
 */
final class IssuedInFutureException extends ClaimValidationException {}
