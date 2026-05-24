<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

/**
 * Immutable view over a parsed JOSE protected header.
 */
final readonly class Header
{
    /** @param array<string, mixed> $values structurally validated by CompactSerializer */
    public function __construct(private array $values) {}

    public function algorithm(): string
    {
        /** @var string */
        return $this->values['alg'];
    }

    public function type(): ?string
    {
        $v = $this->values['typ'] ?? null;

        return is_string($v) ? $v : null;
    }

    public function contentType(): ?string
    {
        $v = $this->values['cty'] ?? null;

        return is_string($v) ? $v : null;
    }

    public function keyId(): ?string
    {
        $v = $this->values['kid'] ?? null;

        return is_string($v) ? $v : null;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->values);
    }

    public function get(string $name): mixed
    {
        return $this->values[$name] ?? null;
    }

    /** @return array<string, mixed> */
    public function all(): array
    {
        return $this->values;
    }
}
