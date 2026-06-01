<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

/**
 * `ECDH-ES+A128KW` — ECDH-ES agreement deriving a 128-bit AES Key Wrap KEK
 * (RFC 7518 §4.6).
 */
final class EcdhEsA128Kw extends EcdhEsAesKw
{
    public function name(): string
    {
        return 'ECDH-ES+A128KW';
    }

    protected function kekByteLength(): int
    {
        return 16;
    }
}
