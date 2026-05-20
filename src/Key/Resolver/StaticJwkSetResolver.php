<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key\Resolver;

use Medzuch\Jwt\Exception\KeyNotFoundException;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyResolver;

use function is_string;
use function sprintf;

/**
 * Resolver backed by a fixed in-memory JWK Set.
 *
 * Lookup strategy, in order:
 *   1. If the header has a `kid`, match it.
 *   2. Else if the header has an `alg`, match the first key bound to
 *      that algorithm.
 *   3. Else throw — we refuse to guess.
 *
 * `jku` and `x5u` are ignored even if present (T11 / RFC 8725 §3.10).
 */
final class StaticJwkSetResolver implements KeyResolver
{
    public function __construct(private readonly JwkSet $keys)
    {
    }

    public function resolve(array $header): Key
    {
        $kid = $header['kid'] ?? null;
        if (is_string($kid) && $kid !== '') {
            $key = $this->keys->findByKid($kid);
            if ($key !== null) {
                return $key;
            }
            throw new KeyNotFoundException(sprintf('No key in set matches kid "%s"', $kid));
        }

        $alg = $header['alg'] ?? null;
        if (is_string($alg) && $alg !== '') {
            $key = $this->keys->findForAlgorithm($alg);
            if ($key !== null) {
                return $key;
            }
            throw new KeyNotFoundException(sprintf('No key in set is bound to algorithm "%s"', $alg));
        }

        throw new KeyNotFoundException('Header has neither "kid" nor "alg"; cannot select a key');
    }
}
