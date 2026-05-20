<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key\Resolver;

use Medzuch\Jwt\Exception\KeyNotFoundException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

use function random_bytes;

#[CoversClass(StaticJwkSetResolver::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(JwkSet::class)]
#[UsesClass(Key::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class StaticJwkSetResolverTest extends TestCase
{
    public function testResolvesByKidWhenPresent(): void
    {
        $a = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'a');
        $b = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'b');
        $resolver = new StaticJwkSetResolver(JwkSet::of($a, $b));

        self::assertSame($b, $resolver->resolve(['kid' => 'b', 'alg' => 'HS256']));
    }

    public function testThrowsWhenKidDoesNotMatch(): void
    {
        $resolver = new StaticJwkSetResolver(JwkSet::of(
            HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'real'),
        ));

        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageMatches('/kid "ghost"/');

        $resolver->resolve(['kid' => 'ghost', 'alg' => 'HS256']);
    }

    public function testFallsBackToAlgWhenNoKid(): void
    {
        $a = HmacKey::fromBinary(random_bytes(32), 'HS256');
        $resolver = new StaticJwkSetResolver(JwkSet::of($a));

        self::assertSame($a, $resolver->resolve(['alg' => 'HS256']));
    }

    public function testThrowsWhenAlgDoesNotMatch(): void
    {
        $resolver = new StaticJwkSetResolver(JwkSet::of(
            HmacKey::fromBinary(random_bytes(32), 'HS256'),
        ));

        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageMatches('/algorithm "HS512"/');

        $resolver->resolve(['alg' => 'HS512']);
    }

    public function testThrowsWhenHeaderHasNeitherKidNorAlg(): void
    {
        $resolver = new StaticJwkSetResolver(JwkSet::of(
            HmacKey::fromBinary(random_bytes(32), 'HS256'),
        ));

        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageMatches('/neither "kid" nor "alg"/');

        $resolver->resolve(['typ' => 'JWT']);
    }

    public function testIgnoresJkuAndX5uEvenIfPresent(): void
    {
        // RFC 8725 §3.10 — `jku` and `x5u` must not be followed by default.
        // This resolver should never consult them; it just finds by kid.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k');
        $resolver = new StaticJwkSetResolver(JwkSet::of($key));

        $resolved = $resolver->resolve([
            'kid' => 'k',
            'alg' => 'HS256',
            'jku' => 'https://attacker.example/jwks.json',
            'x5u' => 'https://attacker.example/cert.pem',
        ]);

        self::assertSame($key, $resolved);
    }

    public function testEmptyKidStringIsIgnored(): void
    {
        // A blank kid should not match anything; we fall through to alg.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');
        $resolver = new StaticJwkSetResolver(JwkSet::of($key));

        self::assertSame($key, $resolver->resolve(['kid' => '', 'alg' => 'HS256']));
    }
}
