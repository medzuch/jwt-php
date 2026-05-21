<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;

/**
 * RFC 7517 JWK Set: an ordered list of keys with `kid` / `alg` lookups.
 *
 * Resolution is "first match wins" — order of insertion matters for key
 * rotation windows (older keys after the newest, both valid until the
 * old one ages out).
 */
final class JwkSet
{
    /**
     * @param list<Key> $keys
     */
    private function __construct(private readonly array $keys) {}

    /**
     * Build a set directly from already-parsed Key instances.
     */
    public static function of(Key ...$keys): self
    {
        return new self(array_values($keys));
    }

    /**
     * Build a set from the `keys` array of an RFC 7517 JWK Set document.
     *
     * @param array<array-key, array<string, mixed>> $keys
     *
     * @throws InvalidKeyException
     */
    public static function fromArray(array $keys): self
    {
        if (!array_is_list($keys)) {
            throw new InvalidKeyException('JWK Set "keys" must be a JSON array');
        }

        return new self(array_map(
            static fn(array $jwk): Key => JwkParser::parse($jwk),
            $keys,
        ));
    }

    /**
     * @return list<Key>
     */
    public function all(): array
    {
        return $this->keys;
    }

    public function count(): int
    {
        return count($this->keys);
    }

    /**
     * First key whose `kid` matches, or null.
     */
    public function findByKid(string $kid): ?Key
    {
        foreach ($this->keys as $key) {
            if ($key->kid() === $kid) {
                return $key;
            }
        }

        return null;
    }

    /**
     * First key whose `alg` matches, or null.
     */
    public function findForAlgorithm(string $alg): ?Key
    {
        foreach ($this->keys as $key) {
            if ($key->alg() === $alg) {
                return $key;
            }
        }

        return null;
    }

    /**
     * Serialise back to an RFC 7517 JWK Set array.
     *
     * @return array{keys: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'keys' => array_map(static fn(Key $k): array => $k->toJwk(), $this->keys),
        ];
    }
}
