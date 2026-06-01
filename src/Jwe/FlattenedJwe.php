<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe;

use Stringable;

/**
 * The RFC 7516 §7.2.2 *flattened* JWE JSON Serialization — a single JSON object
 * for the common single-recipient case, with that recipient's `header` and
 * `encrypted_key` hoisted to the top level instead of nested in a `recipients`
 * array:
 * `{"protected":…,"unprotected":…,"header":…,"encrypted_key":…,"iv":…,"ciphertext":…,"tag":…,"aad":…}`.
 *
 * A typed wrapper around the serialized JSON text, the JSON counterpart to
 * {@see CompactJwe}, so the public API never passes a bare `string` for "the
 * encrypted token". No validation runs in the constructor — this object is
 * produced by {@see Encrypter} (known-good) or wraps bytes received from the
 * network that will be handed to {@see JsonSerializer::deserialize()}.
 */
final readonly class FlattenedJwe implements Stringable
{
    public function __construct(public string $value) {}

    public function __toString(): string
    {
        return $this->value;
    }
}
