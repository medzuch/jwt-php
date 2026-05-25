<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key\Resolver;

use DateInterval;
use Medzuch\Jwt\Exception\JwksResolutionException;
use Medzuch\Jwt\Exception\KeyNotFoundException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\JwkParser;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\Resolver\RemoteJwksResolver;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\Utf8;
use Medzuch\Jwt\Tests\Support\FakeTransportException;
use Medzuch\Jwt\Tests\Support\InMemoryCache;
use Medzuch\Jwt\Tests\Support\QueueingPsr18Client;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

#[CoversClass(RemoteJwksResolver::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(FrozenClock::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(JwkParser::class)]
#[UsesClass(JwkSet::class)]
#[UsesClass(Json::class)]
#[UsesClass(Key::class)]
#[UsesClass(StaticJwkSetResolver::class)]
#[UsesClass(Utf8::class)]
final class RemoteJwksResolverTest extends TestCase
{
    private const URI = 'https://issuer.example/.well-known/jwks.json';

    private Psr17Factory $http;
    private QueueingPsr18Client $client;
    private InMemoryCache $cache;
    private FrozenClock $clock;

    protected function setUp(): void
    {
        $this->http = new Psr17Factory();
        $this->client = new QueueingPsr18Client();
        $this->cache = new InMemoryCache();
        $this->clock = FrozenClock::at('2026-05-21T00:00:00+00:00');
    }

    public function testResolvesKeyFromRemoteEndpoint(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $this->client->enqueue($this->jwksResponse($key));

        $resolved = $this->resolver()->resolve(['kid' => 'k1', 'alg' => 'HS256']);

        self::assertSame('k1', $resolved->kid());
        self::assertSame(1, $this->client->calls);
    }

    public function testSecondLookupIsServedFromCache(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $this->client->enqueue($this->jwksResponse($key));

        $resolver = $this->resolver();
        $resolver->resolve(['kid' => 'k1', 'alg' => 'HS256']);
        $resolver->resolve(['kid' => 'k1', 'alg' => 'HS256']);

        self::assertSame(1, $this->client->calls);
    }

    public function testNonHttpsUriIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/https/');

        new RemoteJwksResolver('http://issuer.example/jwks.json', $this->client, $this->http, $this->cache, $this->clock);
    }

    public function testZeroCacheTtlIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new RemoteJwksResolver(self::URI, $this->client, $this->http, $this->cache, $this->clock, cacheTtlSeconds: 0);
    }

    public function testZeroMinRefreshIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new RemoteJwksResolver(self::URI, $this->client, $this->http, $this->cache, $this->clock, minRefreshSeconds: 0);
    }

    public function testZeroMaxBodyBytesIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new RemoteJwksResolver(self::URI, $this->client, $this->http, $this->cache, $this->clock, maxBodyBytes: 0);
    }

    public function testBoundaryConfigValuesOfOneAreAccepted(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $this->client->enqueue($this->jwksResponse($key));

        $resolver = new RemoteJwksResolver(
            self::URI,
            $this->client,
            $this->http,
            $this->cache,
            $this->clock,
            cacheTtlSeconds: 1,
            minRefreshSeconds: 1,
        );

        self::assertSame('k1', $resolver->resolve(['kid' => 'k1', 'alg' => 'HS256'])->kid());
    }

    public function testHttpErrorStatusThrows(): void
    {
        $this->client->enqueue($this->http->createResponse(404));

        $this->expectException(JwksResolutionException::class);
        $this->expectExceptionMessageMatches('/HTTP 404/');

        $this->resolver()->resolve(['kid' => 'k1']);
    }

    public function testTransportFailureThrows(): void
    {
        $this->client->enqueue(new FakeTransportException('connection refused'));

        $this->expectException(JwksResolutionException::class);
        $this->expectExceptionMessageMatches('/connection refused/');

        $this->resolver()->resolve(['kid' => 'k1']);
    }

    public function testOversizedBodyIsRejected(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $this->client->enqueue($this->jwksResponse($key));

        $resolver = new RemoteJwksResolver(self::URI, $this->client, $this->http, $this->cache, $this->clock, maxBodyBytes: 16);

        $this->expectException(JwksResolutionException::class);
        $this->expectExceptionMessageMatches('/exceeds the 16-byte limit/');

        $resolver->resolve(['kid' => 'k1']);
    }

    public function testDocumentWithoutKeysArrayIsRejected(): void
    {
        $this->client->enqueue($this->jsonResponse(200, '{"not_keys":[]}'));

        $this->expectException(JwksResolutionException::class);
        $this->expectExceptionMessageMatches('/no "keys" array/');
        // The "no keys" diagnostic is raised directly, not re-wrapped by the
        // generic parse-failure handler.
        $this->expectExceptionMessageMatches('/^(?!.*not a valid JWK Set).*$/');

        $this->resolver()->resolve(['kid' => 'k1']);
    }

    public function testMalformedJsonIsRejected(): void
    {
        $this->client->enqueue($this->jsonResponse(200, 'not json at all'));

        $this->expectException(JwksResolutionException::class);
        $this->expectExceptionMessageMatches('/not a valid JWK Set/');

        $this->resolver()->resolve(['kid' => 'k1']);
    }

    public function testRefreshesOnMissAfterRotationWindow(): void
    {
        $k1 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $k2 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k2');
        $this->client->enqueue($this->jwksResponse($k1));        // initial set
        $this->client->enqueue($this->jwksResponse($k1, $k2));   // after issuer rotates

        $resolver = $this->resolver();
        $resolver->resolve(['kid' => 'k1', 'alg' => 'HS256']);   // fetch #1

        // A token signed with the freshly rotated key arrives; advance past
        // the refresh throttle so the resolver is allowed to refetch.
        $this->clock->tick(new DateInterval('PT61S'));
        $resolved = $resolver->resolve(['kid' => 'k2', 'alg' => 'HS256']);

        self::assertSame('k2', $resolved->kid());
        self::assertSame(2, $this->client->calls);
    }

    public function testRefreshIsAllowedExactlyAtTheThrottleBoundary(): void
    {
        $k1 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $k2 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k2');
        $this->client->enqueue($this->jwksResponse($k1));
        $this->client->enqueue($this->jwksResponse($k1, $k2));

        // Default throttle is 60s; advancing exactly 60s must permit a
        // refresh (the boundary is inclusive).
        $resolver = $this->resolver();
        $resolver->resolve(['kid' => 'k1', 'alg' => 'HS256']);
        $this->clock->tick(new DateInterval('PT60S'));

        self::assertSame('k2', $resolver->resolve(['kid' => 'k2', 'alg' => 'HS256'])->kid());
        self::assertSame(2, $this->client->calls);
    }

    public function testRefreshOnMissIsThrottled(): void
    {
        $k1 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $this->client->enqueue($this->jwksResponse($k1));

        $resolver = $this->resolver();
        $resolver->resolve(['kid' => 'k1', 'alg' => 'HS256']);   // fetch #1

        // Immediately ask for an unknown kid: within the throttle window, so
        // no second fetch is attempted — the miss is surfaced as-is.
        try {
            $resolver->resolve(['kid' => 'k2', 'alg' => 'HS256']);
            self::fail('Expected KeyNotFoundException');
        } catch (KeyNotFoundException) {
        }

        self::assertSame(1, $this->client->calls);
    }

    public function testFailedRefreshStillThrottlesSubsequentMisses(): void
    {
        $k1 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $this->client->enqueue($this->jwksResponse($k1));        // cold fetch succeeds
        $this->client->enqueue($this->http->createResponse(500)); // refresh attempt fails
        // No third response is queued: if the throttle did NOT hold, the
        // next miss would attempt another fetch and blow up here.

        $resolver = $this->resolver();
        $resolver->resolve(['kid' => 'k1', 'alg' => 'HS256']);   // fetch #1, stamps the clock

        // Endpoint has since gone bad. Past the throttle window, the first
        // unknown-kid token triggers one refresh — which fails.
        $this->clock->tick(new DateInterval('PT61S'));
        try {
            $resolver->resolve(['kid' => 'k2', 'alg' => 'HS256']);
            self::fail('Expected the failed refresh to surface');
        } catch (JwksResolutionException) {
        }

        // A second unknown-kid token arrives within the window. Because the
        // failed attempt reset the throttle clock, it must NOT refetch.
        $this->clock->tick(new DateInterval('PT1S'));
        try {
            $resolver->resolve(['kid' => 'k2', 'alg' => 'HS256']);
            self::fail('Expected a throttled miss');
        } catch (KeyNotFoundException) {
        }

        self::assertSame(2, $this->client->calls);
    }

    private function resolver(): RemoteJwksResolver
    {
        return new RemoteJwksResolver(self::URI, $this->client, $this->http, $this->cache, $this->clock);
    }

    private function jwksResponse(Key ...$keys): ResponseInterface
    {
        return $this->jsonResponse(200, json_encode(JwkSet::of(...$keys)->toArray(), JSON_THROW_ON_ERROR));
    }

    private function jsonResponse(int $status, string $body): ResponseInterface
    {
        return $this->http->createResponse($status)->withBody($this->http->createStream($body));
    }
}
