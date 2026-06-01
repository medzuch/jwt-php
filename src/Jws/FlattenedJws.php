<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Stringable;

/**
 * The RFC 7515 §7.2.2 flattened JSON serialization of a JWS — a single
 * signature represented as a top-level JSON object whose members are
 * `payload`, `protected`, `header`, and `signature` (any of the last three
 * may be absent).
 *
 * The JSON-flat counterpart to {@see CompactJws}: a typed wrapper so the
 * public API never passes a bare `string` for "the JSON-encoded token". No
 * validation runs in the constructor — this object is produced by
 * {@see Signer::signFlattened()} (known good) or wraps bytes received from
 * the network that will be handed to {@see JsonSerializer::deserialize()}.
 */
final readonly class FlattenedJws implements Stringable
{
    public function __construct(public string $value) {}

    public function __toString(): string
    {
        return $this->value;
    }
}
