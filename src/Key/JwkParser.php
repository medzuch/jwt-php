<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;

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
    private function __construct() {}

    /**
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function parse(array $jwk): Key
    {
        $kty = JwkAttributes::requireString($jwk, 'kty');

        return match ($kty) {
            'oct' => self::octKey($jwk),
            'RSA' => array_key_exists('d', $jwk)
                ? RsaPrivateKey::fromJwk($jwk)
                : RsaPublicKey::fromJwk($jwk),
            'EC' => array_key_exists('d', $jwk)
                ? EcPrivateKey::fromJwk($jwk)
                : EcPublicKey::fromJwk($jwk),
            'OKP' => array_key_exists('d', $jwk)
                ? OkpPrivateKey::fromJwk($jwk)
                : OkpPublicKey::fromJwk($jwk),
            default => throw new InvalidKeyException(sprintf('JWK kty "%s" is not supported (library accepts oct, RSA, EC, OKP)', $kty)),
        };
    }

    /**
     * An `oct` JWK is either an HMAC signing secret ({@see HmacKey}) or a JWE
     * symmetric key ({@see OctKey}). The `alg` decides: `HS*` is HMAC, anything
     * else is routed to {@see OctKey}, which validates the binding itself.
     *
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    private static function octKey(array $jwk): Key
    {
        $alg = JwkAttributes::requireString($jwk, 'alg');

        return str_starts_with($alg, 'HS') ? HmacKey::fromJwk($jwk) : OctKey::fromJwk($jwk);
    }
}
