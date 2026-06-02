<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Stringable;

/**
 * The RFC 7515 §7.2.1 general JSON serialization of a JWS — a top-level
 * JSON object with `payload` and a `signatures` array. Each element of
 * `signatures` carries its own `protected` and/or `header` plus the
 * `signature` value; the `payload` is shared.
 *
 * A typed wrapper around the JSON string, paralleling {@see FlattenedJws}
 * for the flattened form and {@see CompactJws} for the compact form.
 * Multiple signatures are the point of this serialization — a single
 * payload signed under different algorithms / keys for different
 * recipients.
 */
final readonly class GeneralJws implements Stringable
{
    public function __construct(public string $value) {}

    public function __toString(): string
    {
        return $this->value;
    }
}
