<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement;

/**
 * `ECDH-ES+A192KW` — ECDH-ES agreement deriving a 192-bit AES Key Wrap KEK
 * (RFC 7518 §4.6).
 */
final class EcdhEsA192Kw extends EcdhEsAesKw
{
    public function name(): string
    {
        return 'ECDH-ES+A192KW';
    }

    protected function kekByteLength(): int
    {
        return 24;
    }
}
