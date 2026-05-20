<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

/**
 * Marker for keys that can verify signatures (and, in Phase 3, encrypt).
 *
 * Algorithms declare which marker they accept via parameter type. An
 * HMAC algorithm accepting only `HmacKey` cannot be tricked into
 * verifying with an `RsaPublicKey` — that is the McLean confusion
 * mitigation enforced at the type system level.
 */
interface PublicKey
{
}
