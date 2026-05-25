<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Support;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Throwable;

/**
 * A PSR-18 client that hands back queued responses (or throws queued
 * exceptions) in order, counting calls so tests can assert that caching
 * suppressed a network round-trip.
 */
final class QueueingPsr18Client implements \Psr\Http\Client\ClientInterface
{
    /** @var list<ResponseInterface|Throwable> */
    private array $queue = [];

    public int $calls = 0;

    public function enqueue(ResponseInterface|Throwable $response): void
    {
        $this->queue[] = $response;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        ++$this->calls;

        $next = array_shift($this->queue);
        if ($next === null) {
            throw new RuntimeException('QueueingPsr18Client: no response queued for this request');
        }
        if ($next instanceof Throwable) {
            throw $next;
        }

        return $next;
    }
}
