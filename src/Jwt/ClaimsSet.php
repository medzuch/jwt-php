<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

use DateTimeImmutable;
use Medzuch\Jwt\Exception\ClaimTypeException;

/**
 * Immutable view over a parsed JWT Claims Set (RFC 7519 §4).
 *
 * Registered-claim accessors return null when absent. Typed accessors
 * (`getString`, `getInt`, ...) throw on shape mismatch rather than
 * returning a falsy value.
 */
final readonly class ClaimsSet
{
    /** @param array<string, mixed> $claims */
    public function __construct(private array $claims) {}

    public function issuer(): ?string
    {
        return $this->getString('iss');
    }

    public function subject(): ?string
    {
        return $this->getString('sub');
    }

    /**
     * Always a list, even when the token's `aud` is a single string
     * (RFC 7519 §4.1.3 allows both shapes).
     *
     * @return list<string>
     */
    public function audience(): array
    {
        if (!array_key_exists('aud', $this->claims)) {
            return [];
        }
        $aud = $this->claims['aud'];
        if (is_string($aud)) {
            return [$aud];
        }
        // RFC 7519 §4.1.3: `aud` is either a single StringOrURI or a JSON
        // array (list) of them. A JSON object would arrive as an
        // associative PHP array — explicitly refuse, otherwise the
        // foreach would silently drop the keys.
        if (!is_array($aud) || !array_is_list($aud)) {
            throw new ClaimTypeException('Claim "aud" must be a string or list of strings');
        }
        $out = [];
        foreach ($aud as $entry) {
            if (!is_string($entry)) {
                throw new ClaimTypeException('Claim "aud" must contain only strings');
            }
            $out[] = $entry;
        }

        return $out;
    }

    public function expiresAt(): ?DateTimeImmutable
    {
        return $this->toTimestamp('exp');
    }

    public function notBefore(): ?DateTimeImmutable
    {
        return $this->toTimestamp('nbf');
    }

    public function issuedAt(): ?DateTimeImmutable
    {
        return $this->toTimestamp('iat');
    }

    public function jwtId(): ?string
    {
        return $this->getString('jti');
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->claims);
    }

    public function get(string $name): mixed
    {
        return $this->claims[$name] ?? null;
    }

    public function getString(string $name): ?string
    {
        if (!array_key_exists($name, $this->claims)) {
            return null;
        }
        $v = $this->claims[$name];
        if (!is_string($v)) {
            throw new ClaimTypeException(sprintf('Claim "%s" is not a string', $name));
        }

        return $v;
    }

    public function getInt(string $name): ?int
    {
        if (!array_key_exists($name, $this->claims)) {
            return null;
        }
        $v = $this->claims[$name];
        if (!is_int($v)) {
            throw new ClaimTypeException(sprintf('Claim "%s" is not an int', $name));
        }

        return $v;
    }

    public function getBool(string $name): ?bool
    {
        if (!array_key_exists($name, $this->claims)) {
            return null;
        }
        $v = $this->claims[$name];
        if (!is_bool($v)) {
            throw new ClaimTypeException(sprintf('Claim "%s" is not a bool', $name));
        }

        return $v;
    }

    /** @return list<string>|null */
    public function getList(string $name): ?array
    {
        if (!array_key_exists($name, $this->claims)) {
            return null;
        }
        $v = $this->claims[$name];
        if (!is_array($v)) {
            throw new ClaimTypeException(sprintf('Claim "%s" is not a list', $name));
        }
        $expected = 0;
        $out = [];
        foreach ($v as $i => $entry) {
            if ($i !== $expected || !is_string($entry)) {
                throw new ClaimTypeException(sprintf('Claim "%s" is not a list of strings', $name));
            }
            $out[] = $entry;
            ++$expected;
        }

        return $out;
    }

    /** @return array<string, mixed> */
    public function all(): array
    {
        return $this->claims;
    }

    /**
     * Numeric-date claim (RFC 7519 §2) — seconds since the Unix epoch.
     */
    private function toTimestamp(string $name): ?DateTimeImmutable
    {
        if (!array_key_exists($name, $this->claims)) {
            return null;
        }
        $v = $this->claims[$name];
        if (!is_int($v)) {
            throw new ClaimTypeException(sprintf('Claim "%s" must be a NumericDate (int seconds)', $name));
        }

        return (new DateTimeImmutable('@' . $v))->setTimezone(new \DateTimeZone('UTC'));
    }
}
