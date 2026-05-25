<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe;

use Stringable;

/**
 * The RFC 7516 §7.1 compact serialization of a JWE — five base64url segments
 * joined by dots:
 * `BASE64URL(header).BASE64URL(encryptedKey).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)`.
 *
 * The JWE counterpart to {@see \Medzuch\Jwt\Jws\CompactJws}: a typed wrapper
 * so the public API never passes a bare `string` for "the encrypted token".
 * No validation runs in the constructor — this object is produced by
 * {@see \Medzuch\Jwt\Jwe\Encrypter} (known-good) or wraps bytes received from
 * the network that will be handed to {@see CompactSerializer::deserialize()}.
 */
final readonly class CompactJwe implements Stringable
{
    public function __construct(public string $value) {}

    public function __toString(): string
    {
        return $this->value;
    }
}
