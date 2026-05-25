<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key\Resolver;

use InvalidArgumentException;
use Medzuch\Jwt\Exception\JwksResolutionException;
use Medzuch\Jwt\Exception\KeyNotFoundException;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyResolver;
use Medzuch\Jwt\Primitives\Json;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\SimpleCache\CacheInterface;
use Throwable;

/**
 * Resolves verification keys from a remote `jwks_uri` (RFC 8414 / OpenID
 * Connect Discovery), with a PSR-16 cache in front of a PSR-18 client.
 *
 * Posture:
 *
 *  - **HTTPS only.** A plaintext `jwks_uri` is rejected at construction —
 *    fetching keys over a channel an attacker can rewrite defeats the
 *    point (RFC 8725 §3.10, T11). `jku`/`x5u` in the token are never
 *    consulted; the endpoint is fixed by the application.
 *  - **Bounded body.** Responses larger than {@see $maxBodyBytes} are
 *    refused before parsing, so a hostile or broken endpoint cannot
 *    exhaust memory.
 *  - **Cached.** The raw document is cached for {@see $cacheTtlSeconds};
 *    the common path never touches the network.
 *  - **Throttled refresh-on-miss.** When a `kid` is absent from the cached
 *    set the issuer may have rotated, so the document is refetched once and
 *    the lookup retried — but no more often than {@see $minRefreshSeconds},
 *    so a stream of tokens bearing unknown `kid`s cannot be amplified into
 *    a fetch storm against the endpoint.
 *
 * Transport, HTTP-status, size, and parse failures all surface as
 * {@see JwksResolutionException} (a {@see \Medzuch\Jwt\Exception\JwtException}),
 * so a {@see CompositeResolver} can fall through to a local set of
 * still-valid keys when the endpoint is unavailable.
 *
 * Connection and response timeouts are the responsibility of the injected
 * PSR-18 client — configure them there; this resolver cannot enforce a
 * socket timeout on a client it does not own.
 */
final class RemoteJwksResolver implements KeyResolver
{
    private const DEFAULT_MAX_BODY_BYTES = 256 * 1024;
    private const DEFAULT_CACHE_TTL_SECONDS = 300;
    private const DEFAULT_MIN_REFRESH_SECONDS = 60;

    private readonly string $cacheKey;
    private readonly string $timestampKey;

    public function __construct(
        private readonly string $jwksUri,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly int $cacheTtlSeconds = self::DEFAULT_CACHE_TTL_SECONDS,
        private readonly int $minRefreshSeconds = self::DEFAULT_MIN_REFRESH_SECONDS,
        private readonly int $maxBodyBytes = self::DEFAULT_MAX_BODY_BYTES,
    ) {
        if (stripos($jwksUri, 'https://') !== 0) {
            throw new InvalidArgumentException('jwks_uri must be an https:// URL (RFC 8725 §3.10)');
        }
        if ($cacheTtlSeconds < 1 || $minRefreshSeconds < 1 || $maxBodyBytes < 1) {
            throw new InvalidArgumentException('cacheTtlSeconds, minRefreshSeconds, and maxBodyBytes must all be positive');
        }

        // PSR-16 forbids {}()/\@: in keys; a hash of the URI is safe and
        // keeps distinct endpoints from colliding in a shared cache.
        $digest = hash('sha256', $jwksUri);
        $this->cacheKey = 'jwks_' . $digest;
        $this->timestampKey = 'jwks_' . $digest . '_ts';
    }

    public function resolve(array $header): Key
    {
        $set = $this->cachedSet() ?? $this->fetchAndCache();

        try {
            return (new StaticJwkSetResolver($set))->resolve($header);
        } catch (KeyNotFoundException $miss) {
            if (!$this->mayRefresh()) {
                throw $miss;
            }

            // Possible rotation: refetch once and retry. A still-missing
            // kid rethrows the original-style miss from the fresh set.
            return (new StaticJwkSetResolver($this->fetchAndCache()))->resolve($header);
        }
    }

    private function cachedSet(): ?JwkSet
    {
        $body = $this->cache->get($this->cacheKey);

        return is_string($body) ? $this->parse($body) : null;
    }

    private function fetchAndCache(): JwkSet
    {
        $body = $this->fetch();
        $set = $this->parse($body);

        $this->cache->set($this->cacheKey, $body, $this->cacheTtlSeconds);
        $this->cache->set($this->timestampKey, $this->clock->now()->getTimestamp(), $this->cacheTtlSeconds);

        return $set;
    }

    private function fetch(): string
    {
        $request = $this->requestFactory->createRequest('GET', $this->jwksUri);

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new JwksResolutionException(sprintf('JWKS fetch from "%s" failed: %s', $this->jwksUri, $e->getMessage()), 0, $e);
        }

        $status = $response->getStatusCode();
        if ($status !== 200) {
            throw new JwksResolutionException(sprintf('JWKS endpoint "%s" returned HTTP %d', $this->jwksUri, $status));
        }

        $body = (string) $response->getBody();
        if (strlen($body) > $this->maxBodyBytes) {
            throw new JwksResolutionException(sprintf('JWKS response from "%s" exceeds the %d-byte limit', $this->jwksUri, $this->maxBodyBytes));
        }

        return $body;
    }

    private function parse(string $body): JwkSet
    {
        try {
            $document = Json::decode($body);
            $keys = $document['keys'] ?? null;
            if (!is_array($keys) || !array_is_list($keys)) {
                throw new JwksResolutionException('JWKS document has no "keys" array (RFC 7517 §5)');
            }

            /** @var list<array<string, mixed>> $keys */
            return JwkSet::fromArray($keys);
        } catch (JwksResolutionException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new JwksResolutionException(sprintf('JWKS document from "%s" is not a valid JWK Set: %s', $this->jwksUri, $e->getMessage()), 0, $e);
        }
    }

    /**
     * True if enough time has passed since the last successful fetch to
     * justify another one. Absent timestamp means we have never fetched,
     * so a refresh is always allowed.
     */
    private function mayRefresh(): bool
    {
        $last = $this->cache->get($this->timestampKey);
        if (!is_int($last)) {
            return true;
        }

        return $this->clock->now()->getTimestamp() - $last >= $this->minRefreshSeconds;
    }
}
