<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key\Internal;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\KeyUse;

/**
 * Shared parsers for the common JWK attributes (`kid`, `alg`, `use`,
 * `key_ops`, base64url-encoded parameters).
 *
 * @internal Used by HmacKey, RsaPublicKey, RsaPrivateKey, JwkParser.
 *           Not part of the public API.
 */
final class JwkAttributes
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * @param array<string, mixed> $jwk
     *
     * @return non-empty-string
     *
     * @throws InvalidKeyException
     */
    public static function requireString(array $jwk, string $param): string
    {
        if (!array_key_exists($param, $jwk)) {
            throw new InvalidKeyException(sprintf('JWK is missing required "%s" parameter', $param));
        }
        $value = $jwk[$param];
        if (!is_string($value) || $value === '') {
            throw new InvalidKeyException(sprintf('JWK "%s" must be a non-empty string', $param));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $jwk
     *
     * @return non-empty-string|null
     *
     * @throws InvalidKeyException
     */
    public static function optionalString(array $jwk, string $param): ?string
    {
        if (!array_key_exists($param, $jwk)) {
            return null;
        }
        $value = $jwk[$param];
        if (!is_string($value) || $value === '') {
            throw new InvalidKeyException(sprintf('JWK "%s" must be a non-empty string', $param));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $jwk
     *
     * @throws InvalidKeyException
     */
    public static function optionalKeyUse(array $jwk): ?KeyUse
    {
        $value = self::optionalString($jwk, 'use');
        if ($value === null) {
            return null;
        }

        return KeyUse::tryFrom($value)
            ?? throw new InvalidKeyException(sprintf('JWK "use" must be "sig" or "enc", got "%s"', $value));
    }

    /**
     * @param array<string, mixed> $jwk
     *
     * @return list<non-empty-string>|null
     *
     * @throws InvalidKeyException
     */
    public static function optionalKeyOps(array $jwk): ?array
    {
        if (!array_key_exists('key_ops', $jwk)) {
            return null;
        }
        $value = $jwk['key_ops'];
        if (!is_array($value) || !array_is_list($value)) {
            throw new InvalidKeyException('JWK "key_ops" must be a JSON array of strings');
        }
        $ops = [];
        foreach ($value as $op) {
            if (!is_string($op) || $op === '') {
                throw new InvalidKeyException('JWK "key_ops" entries must be non-empty strings');
            }
            $ops[] = $op;
        }

        return $ops;
    }
}
