<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Stringable;

/**
 * The RFC 7515 §3.1 compact serialization of a JWS:
 * `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)`.
 *
 * A simple typed wrapper around the string so the public API never passes
 * a plain `string` around for "the encoded token" — callers can spot at a
 * glance whether a function expects raw payload bytes vs. an already-signed
 * compact JWS.
 *
 * No validation runs in the constructor: this object is produced by
 * {@see Signer} (so the string is known-good) or by code that has already
 * received the bytes from the network and will hand them to
 * {@see CompactSerializer::deserialize()} next.
 */
final readonly class CompactJws implements Stringable
{
    public function __construct(public string $value) {}

    public function __toString(): string
    {
        return $this->value;
    }
}
