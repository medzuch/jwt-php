<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use RuntimeException;

/**
 * The compact JWT could not be parsed at the byte/encoding layer.
 *
 * Thrown for invalid base64url, invalid UTF-8, invalid JSON, wrong number
 * of segments, or duplicate JSON keys (RFC 7519 §4).
 */
final class MalformedJwtException extends RuntimeException implements JwtException {}
