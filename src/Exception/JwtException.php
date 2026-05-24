<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use Throwable;

/**
 * Marker interface for every exception thrown by this library.
 *
 * Callers can catch this to handle any JWT-related failure uniformly.
 * Concrete failures are typed leaf classes; see the hierarchy in
 * docs/01-architecture.md.
 */
interface JwtException extends Throwable {}
