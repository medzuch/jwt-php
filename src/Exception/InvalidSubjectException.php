<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * `sub` did not match the validator's expected subject value.
 */
final class InvalidSubjectException extends ClaimValidationException {}
