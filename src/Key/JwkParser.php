<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;

use function array_key_exists;
use function sprintf;

/**
 * Dispatch entry point for "I have a JWK, give me a Key.".
 *
 * Reads `kty` and routes to the right typed parser. Unsupported key
 * types throw — the library does not silently accept curves or algorithms
 * it cannot use.
 */
final class JwkParser
{
    /** @codeCoverageIgnore */
    private function __construct()
    {
    }

    /**
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function parse(array $jwk): Key
    {
        $kty = JwkAttributes::requireString($jwk, 'kty');

        return match ($kty) {
            'oct' => HmacKey::fromJwk($jwk),
            'RSA' => array_key_exists('d', $jwk)
                ? RsaPrivateKey::fromJwk($jwk)
                : RsaPublicKey::fromJwk($jwk),
            default => throw new InvalidKeyException(sprintf('JWK kty "%s" is not supported in Phase 1 (oct, RSA only)', $kty)),
        };
    }
}
