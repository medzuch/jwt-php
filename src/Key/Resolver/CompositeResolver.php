<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key\Resolver;

use InvalidArgumentException;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Exception\KeyNotFoundException;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyResolver;

/**
 * Tries a list of resolvers in order and returns the first key found.
 *
 * The primary use is a key-rotation window: pair a fast local resolver
 * (a {@see StaticJwkSetResolver} over the keys you already trust) with a
 * {@see RemoteJwksResolver} for keys the issuer has rotated to since. Any
 * {@see JwtException} from a resolver — a miss, or a flaky remote endpoint
 * — falls through to the next resolver. Only when every resolver fails
 * does this throw a {@see KeyNotFoundException}, with the individual
 * reasons folded into one message.
 *
 * Order matters: put the cheapest, most-likely-to-hit resolver first so
 * the common path never touches the network.
 */
final class CompositeResolver implements KeyResolver
{
    /** @var non-empty-list<KeyResolver> */
    private readonly array $resolvers;

    public function __construct(KeyResolver ...$resolvers)
    {
        if ($resolvers === []) {
            throw new InvalidArgumentException('CompositeResolver requires at least one resolver');
        }
        $this->resolvers = array_values($resolvers);
    }

    public function resolve(array $header): Key
    {
        $reasons = [];
        foreach ($this->resolvers as $resolver) {
            try {
                return $resolver->resolve($header);
            } catch (JwtException $failure) {
                // A miss (KeyNotFoundException) or a flaky remote
                // (JwksResolutionException) both fall through to the next.
                $reasons[] = $failure->getMessage();
            }
        }

        throw new KeyNotFoundException(sprintf('No resolver could resolve the key (%s)', implode('; ', $reasons)));
    }
}
