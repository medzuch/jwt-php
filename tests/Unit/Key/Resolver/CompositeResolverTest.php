<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key\Resolver;

use Medzuch\Jwt\Exception\KeyNotFoundException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\JwkParser;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\Resolver\CompositeResolver;
use Medzuch\Jwt\Key\Resolver\RemoteJwksResolver;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\Utf8;
use Medzuch\Jwt\Tests\Support\InMemoryCache;
use Medzuch\Jwt\Tests\Support\QueueingPsr18Client;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CompositeResolver::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(FrozenClock::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(JwkParser::class)]
#[UsesClass(JwkSet::class)]
#[UsesClass(Json::class)]
#[UsesClass(Key::class)]
#[UsesClass(RemoteJwksResolver::class)]
#[UsesClass(StaticJwkSetResolver::class)]
#[UsesClass(Utf8::class)]
final class CompositeResolverTest extends TestCase
{
    public function testReturnsFirstResolverHit(): void
    {
        $k1 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $k2 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k2');

        $composite = new CompositeResolver(
            new StaticJwkSetResolver(JwkSet::of($k1)),
            new StaticJwkSetResolver(JwkSet::of($k2)),
        );

        self::assertSame('k1', $composite->resolve(['kid' => 'k1'])->kid());
    }

    public function testFallsThroughToNextResolverOnMiss(): void
    {
        $k1 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $k2 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k2');

        $composite = new CompositeResolver(
            new StaticJwkSetResolver(JwkSet::of($k1)),
            new StaticJwkSetResolver(JwkSet::of($k2)),
        );

        self::assertSame('k2', $composite->resolve(['kid' => 'k2'])->kid());
    }

    public function testThrowsWhenEveryResolverMisses(): void
    {
        $k1 = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');

        $composite = new CompositeResolver(
            new StaticJwkSetResolver(JwkSet::of($k1)),
            new StaticJwkSetResolver(JwkSet::of($k1)),
        );

        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageMatches('/No resolver could resolve/');

        $composite->resolve(['kid' => 'unknown']);
    }

    public function testEmptyResolverListIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/at least one resolver/');

        new CompositeResolver();
    }

    public function testRotationWindowLocalKeyDoesNotTouchNetwork(): void
    {
        $oldKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'old');
        $newKey = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'new');

        [$remote, $client] = $this->remoteServing($newKey);
        $composite = new CompositeResolver(
            new StaticJwkSetResolver(JwkSet::of($oldKey)),
            $remote,
        );

        // The still-trusted local key resolves without any HTTP call.
        self::assertSame('old', $composite->resolve(['kid' => 'old', 'alg' => 'HS256'])->kid());
        self::assertSame(0, $client->calls);

        // A token signed with the rotated-to key falls through to the remote.
        self::assertSame('new', $composite->resolve(['kid' => 'new', 'alg' => 'HS256'])->kid());
        self::assertSame(1, $client->calls);
    }

    /**
     * @return array{RemoteJwksResolver, QueueingPsr18Client}
     */
    private function remoteServing(Key ...$keys): array
    {
        $http = new Psr17Factory();
        $client = new QueueingPsr18Client();
        $body = json_encode(JwkSet::of(...$keys)->toArray(), JSON_THROW_ON_ERROR);
        $client->enqueue($http->createResponse(200)->withBody($http->createStream($body)));

        $resolver = new RemoteJwksResolver(
            'https://issuer.example/jwks.json',
            $client,
            $http,
            new InMemoryCache(),
            FrozenClock::at('2026-05-21T00:00:00+00:00'),
        );

        return [$resolver, $client];
    }
}
