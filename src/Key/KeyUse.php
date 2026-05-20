<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

/**
 * JWK `use` parameter (RFC 7517 §4.2).
 *
 * Either signing/verification or encryption/decryption. The library
 * refuses to use a key flagged for one purpose with the other.
 */
enum KeyUse: string
{
    case Sig = 'sig';
    case Enc = 'enc';
}
