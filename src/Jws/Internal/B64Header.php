<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws\Internal;

use Medzuch\Jwt\Exception\InvalidHeaderException;

/**
 * Shared structural rules for the `b64` / `crit` coupling (RFC 7797 + RFC
 * 7515 §4.1.11). Both ends of the JWS layer must enforce the same shape so
 * a token the {@see \Medzuch\Jwt\Jws\Signer} produces is parseable by the
 * same library's {@see \Medzuch\Jwt\Jws\CompactSerializer} and acceptable
 * to its {@see \Medzuch\Jwt\Jws\Verifier} — a producer must not be able to
 * mint a JWS the consumer side then refuses.
 *
 * Rules enforced (each fails closed with {@see InvalidHeaderException}):
 *
 *   1. `b64`, when present, MUST be a JSON boolean (RFC 7797 §3).
 *   2. `crit`, when present, MUST be a non-empty list of non-empty strings
 *      (RFC 7515 §4.1.11).
 *   3. `crit` MAY list only `"b64"`. Any other extension is refused — that
 *      is the one critical extension this library understands, and §4.1.11
 *      says a JWS with a critical extension the recipient does not
 *      understand is invalid.
 *   4. Every name in `crit` MUST also appear as a member of the protected
 *      header (RFC 7515 §4.1.11). Concretely: `crit:["b64"]` is rejected
 *      unless `b64` is itself a member of the header.
 *   5. When `b64` is `false`, `crit` MUST be present and MUST include
 *      `"b64"` (RFC 7797 §6). The default `b64:true` does not carry this
 *      requirement.
 */
final class B64Header
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * @param array<string, mixed> $header
     *
     * @throws InvalidHeaderException
     */
    public static function assertValid(array $header): void
    {
        $b64Present = array_key_exists('b64', $header);
        $b64 = null;
        if ($b64Present) {
            $value = $header['b64'];
            if (!is_bool($value)) {
                throw new InvalidHeaderException('Header "b64" must be a boolean (RFC 7797 §3)');
            }
            $b64 = $value;
        }

        $critPresent = array_key_exists('crit', $header);
        $crit = null;
        if ($critPresent) {
            $value = $header['crit'];
            if (!self::isNonEmptyStringList($value)) {
                throw new InvalidHeaderException('Header "crit" must be a non-empty list of non-empty strings (RFC 7515 §4.1.11)');
            }
            foreach ($value as $extension) {
                if ($extension !== 'b64') {
                    throw new InvalidHeaderException(sprintf('Header "crit" lists unsupported extension "%s" (RFC 7515 §4.1.11)', $extension));
                }
            }
            $crit = $value;
        }

        // §4.1.11: every name in `crit` must also be a header member. Since
        // only "b64" is admissible at all (rule 3 above), this collapses to
        // "if `b64` is in `crit`, it must also be in the header".
        if ($crit !== null && !$b64Present) {
            throw new InvalidHeaderException('Header "crit" lists "b64" but the "b64" header parameter is not present (RFC 7515 §4.1.11)');
        }

        // §6: the `b64:false` mode is what makes `crit:["b64"]` mandatory.
        // The default (`b64` absent or `true`) does not carry the same
        // requirement — a JWS may declare `b64:true` without listing it in
        // `crit`, even though marking the default critical is meaningless.
        //
        // Rule 3 above admits nothing but "b64" into `crit`, so a non-null
        // `$crit` always lists it: the §6 requirement collapses to "`crit`
        // must be present at all". Re-testing membership here would be dead
        // code, not defence in depth — this function is the only place that
        // establishes the invariant.
        if ($b64 === false && $crit === null) {
            throw new InvalidHeaderException('Header "b64":false requires "crit" to include "b64" (RFC 7797 §6)');
        }
    }

    /**
     * @phpstan-assert-if-true non-empty-list<non-empty-string> $value
     */
    private static function isNonEmptyStringList(mixed $value): bool
    {
        if (!is_array($value) || $value === []) {
            return false;
        }
        $expected = 0;
        foreach ($value as $i => $entry) {
            if ($i !== $expected || !is_string($entry) || $entry === '') {
                return false;
            }
            ++$expected;
        }

        return true;
    }
}
