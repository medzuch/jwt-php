<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe;

use Stringable;

/**
 * The RFC 7516 §7.2.1 *general* JWE JSON Serialization — a single JSON object
 * whose per-recipient `header` / `encrypted_key` live in a `recipients` array:
 * `{"protected":…,"unprotected":…,"recipients":[{"header":…,"encrypted_key":…}],"iv":…,"ciphertext":…,"tag":…,"aad":…}`.
 *
 * The general form is the only one that can address more than one recipient; in
 * this version {@see Encrypter} populates a single-element `recipients` array
 * (multi-recipient production is deferred), but the serialization is emitted in
 * the general shape so consumers see the canonical structure.
 *
 * A typed wrapper around the serialized JSON text, the JSON counterpart to
 * {@see CompactJwe}. No validation runs in the constructor — produced by
 * {@see Encrypter} (known-good) or wrapping bytes that will be handed to
 * {@see JsonSerializer::deserialize()}.
 */
final readonly class GeneralJwe implements Stringable
{
    public function __construct(public string $value) {}

    public function __toString(): string
    {
        return $this->value;
    }
}
