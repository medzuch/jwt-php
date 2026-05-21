<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use RuntimeException;

/**
 * Signature did not verify against the resolved key.
 */
final class SignatureVerificationException extends RuntimeException implements JwtException {}
