<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\ConstantTime;
use Medzuch\Jwt\Primitives\Json;

/**
 * JWK SHA-256 thumbprint of an asymmetric key (RFC 7638) — the value a
 * DPoP-bound access token carries as `cnf.jkt` (RFC 9449 §6.1).
 *
 * The hash input is a JSON object of the key type's **required members
 * only**, in lexicographic order and without whitespace (RFC 7638 §3.2).
 * `Key::toJwk()` emits more than that — `alg`, `kid`, `use`, and for a
 * private key the private parameters — and a digest of it unfiltered
 * matches nothing. Filtering also means a private key and its public half
 * share one thumbprint.
 *
 * Symmetric keys are refused. RFC 7638 §3.2 does define a required set for
 * `oct`, so the table keeps it, but that thumbprint is a digest of the
 * secret itself and no confirmation method binds a token to a shared key.
 * A `SymmetricKey` is refused before `toJwk()` is called, so its secret is
 * never encoded; the `kty` check behind it catches a foreign `Key` subclass
 * that emits `oct`.
 */
final class Thumbprint
{
    /** RFC 7638 §3.2 — required members per `kty`, already in lexicographic order. */
    private const REQUIRED_MEMBERS = [
        'EC' => ['crv', 'kty', 'x', 'y'],
        'OKP' => ['crv', 'kty', 'x'],
        'RSA' => ['e', 'kty', 'n'],
        'oct' => ['k', 'kty'],
    ];

    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * Base64url (unpadded) SHA-256 thumbprint of $key.
     *
     * @throws InvalidKeyException for a symmetric key, or a key whose JWK has
     *                             an unknown `kty` or lacks a required member
     */
    public static function of(Key $key): string
    {
        if ($key instanceof SymmetricKey) {
            throw self::symmetricKeyRefused();
        }

        $jwk = $key->toJwk();
        $kty = $jwk['kty'] ?? null;

        if ($kty === 'oct') {
            throw self::symmetricKeyRefused();
        }
        if (!is_string($kty) || !array_key_exists($kty, self::REQUIRED_MEMBERS)) {
            throw new InvalidKeyException('Cannot thumbprint a key of unknown "kty" (RFC 7638 §3.2)');
        }

        $members = [];
        foreach (self::REQUIRED_MEMBERS[$kty] as $name) {
            $value = $jwk[$name] ?? null;
            if (!is_string($value) || $value === '') {
                throw new InvalidKeyException(sprintf('Cannot thumbprint a "%s" key without its "%s" member (RFC 7638 §3.2)', $kty, $name));
            }
            $members[$name] = $value;
        }

        return Base64Url::encode(hash('sha256', Json::encode($members), true));
    }

    /**
     * True iff $expected is the thumbprint of $key, compared in constant time.
     *
     * @throws InvalidKeyException under the same conditions as {@see of()}
     */
    public static function matches(Key $key, string $expected): bool
    {
        return ConstantTime::equals(self::of($key), $expected);
    }

    private static function symmetricKeyRefused(): InvalidKeyException
    {
        return new InvalidKeyException('Refusing to thumbprint a symmetric key: the digest would be of the secret itself (RFC 7638 §3.2)');
    }
}
