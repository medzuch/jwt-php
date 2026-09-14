<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Support;

use Medzuch\Jwt\Key\Key;

/**
 * A third-party {@see Key} subclass that emits whatever JWK it is given.
 *
 * `Key` is abstract with a protected constructor, so code outside the
 * library can extend it and return any shape from `toJwk()` — including an
 * unknown `kty` or a missing member. Consumers of `toJwk()` that trust its
 * output are tested against this.
 */
final class ForeignJwkKey extends Key
{
    /** @param array<string, mixed> $jwk */
    public function __construct(private readonly array $jwk)
    {
        parent::__construct('FOREIGN');
    }

    public function toJwk(): array
    {
        return $this->jwk;
    }
}
