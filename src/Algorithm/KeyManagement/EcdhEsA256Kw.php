<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

/**
 * `ECDH-ES+A256KW` — ECDH-ES agreement deriving a 256-bit AES Key Wrap KEK
 * (RFC 7518 §4.6).
 */
final class EcdhEsA256Kw extends EcdhEsAesKw
{
    public function name(): string
    {
        return 'ECDH-ES+A256KW';
    }

    protected function kekByteLength(): int
    {
        return 32;
    }
}
