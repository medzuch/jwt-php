<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Unsecured;

use LogicException;
use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Key\PublicKey;

/**
 * `alg: none` — RFC 7515 §3 unsecured JWS. Deliberately on its own
 * namespace (`Algorithm\Unsecured`) so a glob import of the safe
 * `Algorithm\Signing\*` cannot reach it. It is not a default in any
 * shipped allowlist; callers who want it must reference this class by
 * its FQN.
 *
 * The class implements {@see SigningAlgorithm} only so it can be passed
 * to a verifier's allowlist. Neither method is meant to be invoked via
 * the regular Signer/Verifier flow:
 *   - `sign()` throws — use {@see \Medzuch\Jwt\Jwt\Unsecured\UnsecuredJwtBuilder}
 *     to produce alg:none tokens, which short-circuits the signer.
 *   - `verify()` returns true only for the empty signature an unsecured
 *     token actually carries. {@see \Medzuch\Jwt\Jws\CompactSerializer}
 *     refuses empty-signature segments at parse time, so reaching this
 *     verify path requires the caller to bypass CompactSerializer.
 */
final class None implements SigningAlgorithm
{
    public function name(): string
    {
        return 'none';
    }

    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::None;
    }

    public function sign(string $input, PrivateKey $key): string
    {
        throw new LogicException('"none" cannot sign through the standard Signer; use UnsecuredJwtBuilder');
    }

    public function verify(string $input, string $signature, PublicKey $key): bool
    {
        return $signature === '';
    }
}
