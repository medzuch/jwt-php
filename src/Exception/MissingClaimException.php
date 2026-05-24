<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * A claim required by the validator was absent from the token.
 */
final class MissingClaimException extends ClaimValidationException {}
