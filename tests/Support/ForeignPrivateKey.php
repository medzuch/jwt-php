<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Support;

use Medzuch\Jwt\Key\PrivateKey;

/**
 * A signing key that satisfies the public {@see PrivateKey} contract without
 * belonging to this library's own key hierarchy.
 *
 * `PrivateKey` is a bare marker (`interface PrivateKey {}`), and `kid()` is
 * declared on the abstract {@see \Medzuch\Jwt\Key\Key} class rather than on
 * the interface. A third-party key like this one is therefore legal against
 * the public API and has no `kid()` to call — which is exactly why the
 * profiles guard the `kid` header with `instanceof Key` before reading it.
 *
 * Pairs with {@see ForeignSigningAlgorithm}: as with every real algorithm,
 * the strategy — not the profile — is what decides which key shapes it
 * accepts.
 */
final class ForeignPrivateKey implements PrivateKey
{
    /**
     * @param non-empty-string $secret
     */
    public function __construct(public readonly string $secret = 'foreign-key-secret') {}
}
