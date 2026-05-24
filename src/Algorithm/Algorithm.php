<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm;

/**
 * Base contract every JOSE algorithm satisfies.
 *
 * Algorithms are stateless strategy objects. One class per `alg` value, so
 * the caller-supplied allowlist is just a list of concrete classes — there
 * is no string-keyed registry to confuse, and the McLean class of attacks
 * cannot happen because the key parameter types refuse the wrong key shape
 * at the type-system level.
 *
 * @see SigningAlgorithm for the JWS contract.
 */
interface Algorithm
{
    /**
     * The IANA `alg` registry name, e.g. `"HS256"`, `"RS256"`.
     *
     * @return non-empty-string
     */
    public function name(): string;

    public function family(): AlgorithmFamily;
}
