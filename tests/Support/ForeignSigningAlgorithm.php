<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Support;

use LogicException;
use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Key\PublicKey;

/**
 * A signing strategy living entirely outside this library's key hierarchy,
 * so that {@see ForeignPrivateKey} can be used end to end.
 *
 * The `alg` name is deliberately not an IANA-registered one: nothing here is
 * meant to interoperate, only to prove that the producer side works with a
 * key it did not define. Signing is a plain HMAC over the signing input —
 * enough to make a real, parseable token.
 *
 * Issue-side only: {@see verify()} is never reached, because the consumer
 * side resolves keys from a {@see \Medzuch\Jwt\Key\JwkSet} and so never sees
 * a foreign key.
 */
final class ForeignSigningAlgorithm implements SigningAlgorithm
{
    /** @var non-empty-string */
    public const NAME = 'FOREIGN-HS256';

    public function name(): string
    {
        return self::NAME;
    }

    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::Hmac;
    }

    public function sign(string $input, PrivateKey $key): string
    {
        if (!$key instanceof ForeignPrivateKey) {
            throw new KeyMismatchException(sprintf('%s signs only with %s', self::NAME, ForeignPrivateKey::class));
        }

        return hash_hmac('sha256', $input, $key->secret, true);
    }

    public function verify(string $input, string $signature, PublicKey $key): bool
    {
        throw new LogicException(self::NAME . ' is an issue-side test double and does not verify');
    }
}
