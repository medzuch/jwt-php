<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm;

/**
 * Coarse grouping of JOSE algorithms by underlying primitive.
 *
 * Used by upper layers (key resolvers, profiles) that need to reason about
 * families without enumerating every `alg` name. The set will grow as later
 * phases ship ECDSA, EdDSA, RSA-PSS and the JWE algorithm families.
 */
enum AlgorithmFamily
{
    case Hmac;
    case Rsa;
    case Ecdsa;
    case EdDsa;
    case None;
}
