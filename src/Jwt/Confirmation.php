<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

use LogicException;
use Medzuch\Jwt\Exception\ClaimTypeException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Primitives\Base64Url;

/**
 * The confirmation (`cnf`) claim of a sender-constrained token
 * (RFC 7800 §3.1), modelling the two members that bind an OAuth access
 * token: `jkt`, the RFC 7638 thumbprint of a DPoP key (RFC 9449 §6.1), and
 * `x5t#S256`, the thumbprint of a client certificate (RFC 8705 §3.1).
 *
 * **Reading is not fail-closed.** RFC 7800 §3.1 requires confirmation
 * members an implementation does not understand to be ignored, so a `cnf`
 * carrying `jwk`, `jku` or a member some later specification defines still
 * yields an instance; the accessors for what it does not model answer null.
 * An instance with both accessors null therefore means "bound, by a method
 * this library does not enforce" — distinct from a token with no `cnf` at
 * all, for which {@see ClaimsSet::confirmation()} returns null. Only a `cnf`
 * that is not a JSON object, or a modelled member of the wrong shape, is
 * refused.
 *
 * **Issuing binds one key.** Each named constructor yields a single member,
 * because RFC 7800 §3.1 has the claim "represent only a single
 * proof-of-possession key".
 *
 * Both members are SHA-256 digests encoded as unpadded base64url — exactly
 * 43 characters decoding to 32 bytes. Any other value (a hex digest, padded
 * or standard base64) is refused on both sides: as a `LogicException` from
 * the named constructors, where it is a caller bug, and as a
 * `ClaimTypeException` when read from a token. The check includes
 * canonical encoding, which the `x5t#S256` printed in RFC 8705 §3.1 and
 * §3.2 fails: its final character carries non-zero padding bits, so no
 * certificate's thumbprint could ever equal it. Tests copied from that
 * example should compute a real thumbprint instead.
 */
final readonly class Confirmation
{
    private const JKT = 'jkt';
    private const X5T_S256 = 'x5t#S256';

    private function __construct(
        private ?string $jkt,
        private ?string $x5tS256,
    ) {}

    /**
     * Bind to a DPoP key by its RFC 7638 thumbprint (see {@see \Medzuch\Jwt\Key\Thumbprint::of()}).
     *
     * @throws LogicException if $jkt is not an unpadded base64url SHA-256 digest
     */
    public static function jwkThumbprint(string $jkt): self
    {
        if (!self::isSha256Thumbprint($jkt)) {
            throw new LogicException('Confirmation "jkt" must be an unpadded base64url SHA-256 digest (RFC 9449 §6.1)');
        }

        return new self($jkt, null);
    }

    /**
     * Bind to a client certificate by its RFC 8705 thumbprint (see {@see \Medzuch\Jwt\Key\CertificateThumbprint}).
     *
     * @throws LogicException if $x5tS256 is not an unpadded base64url SHA-256 digest
     */
    public static function certificateThumbprint(string $x5tS256): self
    {
        if (!self::isSha256Thumbprint($x5tS256)) {
            throw new LogicException('Confirmation "x5t#S256" must be an unpadded base64url SHA-256 digest (RFC 8705 §3.1)');
        }

        return new self(null, $x5tS256);
    }

    /**
     * @internal Consumed by {@see ClaimsSet::confirmation()}; not part of the frozen public API.
     *
     * @throws ClaimTypeException
     */
    public static function fromClaim(mixed $cnf): self
    {
        if (!is_array($cnf) || ($cnf !== [] && array_is_list($cnf))) {
            throw new ClaimTypeException('Claim "cnf" must be a JSON object (RFC 7800 §3.1)');
        }

        return new self(
            self::readMember($cnf, self::JKT),
            self::readMember($cnf, self::X5T_S256),
        );
    }

    public function jkt(): ?string
    {
        return $this->jkt;
    }

    public function x5tS256(): ?string
    {
        return $this->x5tS256;
    }

    /**
     * The `cnf` claim value: the modelled members that are present.
     *
     * @return non-empty-array<string, string>
     *
     * @throws LogicException for a confirmation read from a token whose `cnf`
     *                        carries none of the members modelled here — its
     *                        value would otherwise encode as an empty JSON array
     */
    public function toClaim(): array
    {
        $claim = [];
        if ($this->jkt !== null) {
            $claim[self::JKT] = $this->jkt;
        }
        if ($this->x5tS256 !== null) {
            $claim[self::X5T_S256] = $this->x5tS256;
        }
        if ($claim === []) {
            throw new LogicException('Confirmation has neither "jkt" nor "x5t#S256"; read the original with ClaimsSet::get(\'cnf\')');
        }

        return $claim;
    }

    /**
     * @param array<array-key, mixed> $cnf
     *
     * @throws ClaimTypeException
     */
    private static function readMember(array $cnf, string $name): ?string
    {
        if (!array_key_exists($name, $cnf)) {
            return null;
        }
        $value = $cnf[$name];
        if (!is_string($value) || !self::isSha256Thumbprint($value)) {
            throw new ClaimTypeException(sprintf('Claim "cnf" member "%s" must be an unpadded base64url SHA-256 digest', $name));
        }

        return $value;
    }

    private static function isSha256Thumbprint(string $value): bool
    {
        if (strlen($value) !== 43) {
            return false;
        }

        try {
            return strlen(Base64Url::decode($value)) === 32;
        } catch (MalformedJwtException) {
            return false;
        }
    }
}
