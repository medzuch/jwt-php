<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Support;

use Psr\SimpleCache\CacheInterface;

/**
 * Minimal in-memory PSR-16 cache for resolver tests. TTL is intentionally
 * ignored — tests drive time through the injected {@see \Medzuch\Jwt\Primitives\FrozenClock},
 * not through cache expiry.
 */
final class InMemoryCache implements CacheInterface
{
    /** @var array<string, mixed> */
    private array $store = [];

    public int $writes = 0;

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->store[$key] ?? $default;
    }

    public function set(string $key, mixed $value, int|\DateInterval|null $ttl = null): bool
    {
        ++$this->writes;
        $this->store[$key] = $value;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->store[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->store = [];

        return true;
    }

    /**
     * @param iterable<string> $keys
     *
     * @return iterable<string, mixed>
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $out = [];
        foreach ($keys as $key) {
            $out[$key] = $this->get($key, $default);
        }

        return $out;
    }

    /**
     * @param iterable<mixed, mixed> $values
     */
    public function setMultiple(iterable $values, int|\DateInterval|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            \assert(is_string($key) || is_int($key));
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    /**
     * @param iterable<string> $keys
     */
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->store);
    }
}
