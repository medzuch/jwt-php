<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Support;

use Psr\Http\Client\ClientExceptionInterface;
use RuntimeException;

/**
 * A PSR-18 transport failure, for simulating an unreachable JWKS endpoint.
 */
final class FakeTransportException extends RuntimeException implements ClientExceptionInterface {}
