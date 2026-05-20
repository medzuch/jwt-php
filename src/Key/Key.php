<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Exception\KeyMismatchException;

use function in_array;
use function sprintf;

/**
 * Common state for every key the library handles.
 *
 * Each subclass binds itself to exactly one algorithm name (`alg`). The
 * "one key, one algorithm" rule of RFC 8725 §3.1 is enforced here: once
 * `$alg` is set, the algorithm strategy refuses any key whose `alg()`
 * does not match.
 */
abstract class Key
{
    /**
     * @param list<string>|null $keyOps
     *
     * @throws InvalidKeyException
     */
    protected function __construct(
        private readonly string $alg,
        private readonly ?string $kid = null,
        private readonly ?KeyUse $use = null,
        private readonly ?array $keyOps = null,
    ) {
        if ($alg === '') {
            throw new InvalidKeyException('Key algorithm cannot be empty');
        }
        if ($kid === '') {
            throw new InvalidKeyException('Key kid cannot be the empty string; use null instead');
        }
        if ($use !== null && $keyOps !== null) {
            // RFC 7517 §4.3: `use` and `key_ops` SHOULD NOT both be present.
            // We refuse the combination rather than silently picking one.
            throw new InvalidKeyException('Key declares both "use" and "key_ops"; RFC 7517 §4.3 forbids it');
        }

        if ($keyOps !== null && $keyOps === []) {
            throw new InvalidKeyException('"key_ops" must be a non-empty list when present');
        }
    }

    public function alg(): string
    {
        return $this->alg;
    }

    public function kid(): ?string
    {
        return $this->kid;
    }

    public function use(): ?KeyUse
    {
        return $this->use;
    }

    /** @return list<string>|null */
    public function keyOps(): ?array
    {
        return $this->keyOps;
    }

    /**
     * True iff this key is permitted to perform $op (e.g. "sign", "verify").
     *
     * Logic mirrors RFC 7517 §4.3:
     *   - If `key_ops` is present, $op must appear in it.
     *   - Else if `use` is present, $op must be compatible with it
     *     (`sig` permits "sign"/"verify"; `enc` permits "encrypt"/"decrypt"/"wrapKey"/"unwrapKey"/"deriveKey"/"deriveBits").
     *   - Else no constraint — allowed.
     */
    public function allowsOperation(string $op): bool
    {
        if ($this->keyOps !== null) {
            return in_array($op, $this->keyOps, true);
        }

        return match ($this->use) {
            KeyUse::Sig => $op === 'sign' || $op === 'verify',
            KeyUse::Enc => in_array(
                $op,
                ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'],
                true,
            ),
            null => true,
        };
    }

    /**
     * Throw if $algName is not the algorithm this key is bound to.
     *
     * @throws KeyMismatchException
     */
    public function assertAlgorithm(string $algName): void
    {
        if ($this->alg !== $algName) {
            throw new KeyMismatchException(sprintf('Key is bound to algorithm "%s" and cannot be used with "%s" (RFC 8725 §3.1)', $this->alg, $algName));
        }
    }

    /**
     * JWK representation of this key, per RFC 7517.
     *
     * @return array<string, mixed>
     */
    abstract public function toJwk(): array;
}
