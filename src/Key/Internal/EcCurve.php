<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key\Internal;

use Medzuch\Jwt\Exception\InvalidKeyException;

/**
 * Metadata for the JOSE-blessed prime-order NIST curves (RFC 7518 §6.2.1.1).
 *
 * Maps the JWK curve name (`P-256` / `P-384` / `P-521`) to the OpenSSL
 * short name accepted by `openssl_pkey_get_details`, the OID used in the
 * SubjectPublicKeyInfo and ECPrivateKey ASN.1 structures, the coordinate
 * size in bytes for `x` / `y` / `d`, and the matching JWS algorithm name.
 *
 * Note: P-521 has 521-bit order, so the coord size is ⌈521/8⌉ = 66 bytes,
 * not 64. The signature is 132 bytes (r || s), not 128.
 *
 * @internal consumed by {@see \Medzuch\Jwt\Key\EcPublicKey},
 *           {@see \Medzuch\Jwt\Key\EcPrivateKey}, and the ECDSA
 *           algorithm classes.
 */
final class EcCurve
{
    /**
     * SEC 1 §2.3.3 uncompressed-point format octet — prepended to `x || y`
     * inside SubjectPublicKeyInfo and ECPrivateKey BIT STRINGs. RFC 7518
     * §6.2.1.2 mandates uncompressed form for JWK; compressed (`0x02`,
     * `0x03`) and hybrid (`0x06`, `0x07`) forms are intentionally not
     * accepted by this library.
     */
    public const UNCOMPRESSED_POINT = "\x04";

    /**
     * ECDH-ES key-agreement `alg` values (RFC 7518 §4.6). Unlike the ECDSA
     * signing algorithms, these do *not* pin a curve: an ECDH-ES key may sit
     * on any of the supported NIST curves, and the curve is taken from the
     * key's `crv` rather than from the algorithm name.
     */
    public const KEY_AGREEMENT_ALGS = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];

    /**
     * @param non-empty-string $jwkName    e.g. "P-256"
     * @param non-empty-string $opensslName e.g. "prime256v1"
     * @param non-empty-string $oid        e.g. "1.2.840.10045.3.1.7"
     * @param positive-int     $coordSize  byte length of each of x / y / d
     * @param non-empty-string $alg        e.g. "ES256"
     */
    private function __construct(
        public readonly string $jwkName,
        public readonly string $opensslName,
        public readonly string $oid,
        public readonly int $coordSize,
        public readonly string $alg,
    ) {}

    /**
     * @throws InvalidKeyException on unsupported curve names
     */
    public static function fromJwkName(string $name): self
    {
        return match ($name) {
            'P-256' => new self('P-256', 'prime256v1', '1.2.840.10045.3.1.7', 32, 'ES256'),
            'P-384' => new self('P-384', 'secp384r1', '1.3.132.0.34', 48, 'ES384'),
            'P-521' => new self('P-521', 'secp521r1', '1.3.132.0.35', 66, 'ES512'),
            default => throw new InvalidKeyException(sprintf('Unsupported EC curve "%s"; library accepts P-256, P-384, P-521', $name)),
        };
    }

    /**
     * @throws InvalidKeyException on unsupported OpenSSL curve short names
     */
    public static function fromOpensslName(string $name): self
    {
        return match ($name) {
            'prime256v1' => self::fromJwkName('P-256'),
            'secp384r1' => self::fromJwkName('P-384'),
            'secp521r1' => self::fromJwkName('P-521'),
            default => throw new InvalidKeyException(sprintf('Unsupported OpenSSL EC curve "%s"; library accepts prime256v1, secp384r1, secp521r1', $name)),
        };
    }

    /**
     * Whether `$alg` pins the key to one specific curve (the ECDSA signing
     * algorithms) or leaves it free (the ECDH-ES key-agreement algorithms,
     * whose curve comes from the key's `crv`).
     */
    public static function bindsToFixedCurve(string $alg): bool
    {
        return !in_array($alg, self::KEY_AGREEMENT_ALGS, true);
    }

    /**
     * @throws InvalidKeyException on unsupported algorithm names
     */
    public static function fromAlg(string $alg): self
    {
        return match ($alg) {
            'ES256' => self::fromJwkName('P-256'),
            'ES384' => self::fromJwkName('P-384'),
            'ES512' => self::fromJwkName('P-521'),
            default => throw new InvalidKeyException(sprintf('Unsupported ECDSA algorithm "%s"; library accepts ES256, ES384, ES512', $alg)),
        };
    }
}
