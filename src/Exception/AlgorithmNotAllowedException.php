<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use RuntimeException;

/**
 * The token's `alg` is not in the caller-declared allowlist.
 *
 * RFC 8725 §3.1: callers must declare which algorithms are acceptable;
 * the library refuses anything else regardless of what the header claims.
 */
final class AlgorithmNotAllowedException extends RuntimeException implements JwtException {}
