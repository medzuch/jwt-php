<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe\Internal;

use Medzuch\Jwt\Exception\InvalidHeaderException;

/**
 * Shape checks for the *effective* JWE JOSE header — the parameters a recipient
 * will act on, whether they arrived in one compact protected header or were
 * assembled from the protected, shared-unprotected, and per-recipient headers
 * of the JSON serialization (RFC 7516 §7.2.1).
 *
 * Shared by {@see \Medzuch\Jwt\Jwe\CompactSerializer} and
 * {@see \Medzuch\Jwt\Jwe\JsonSerializer} so a parameter that is refused in one
 * serialization is refused in the other — there is no JSON-only escape hatch
 * past the fail-closed `crit`/`zip`/`b64` rejections.
 *
 * @internal
 */
final class JweHeader
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * @param array<string, mixed> $header the effective (merged) JOSE header
     *
     * @throws InvalidHeaderException
     */
    public static function assertShape(array $header): void
    {
        foreach (['alg', 'enc'] as $required) {
            if (!array_key_exists($required, $header)) {
                throw new InvalidHeaderException(sprintf('JWE protected header is missing required "%s"', $required));
            }
            if (!is_string($header[$required]) || $header[$required] === '') {
                throw new InvalidHeaderException(sprintf('JWE protected header "%s" must be a non-empty string', $required));
            }
        }

        // `array_key_exists`, not `isset`: a header that declares one of these
        // with an explicit JSON `null` must be refused too, not treated as
        // absent (RFC 7516 §4).
        if (array_key_exists('crit', $header)) {
            throw new InvalidHeaderException('JWE protected header declares "crit" extensions; this library understands none and RFC 7516 §4.1.13 requires refusal');
        }
        if (array_key_exists('zip', $header)) {
            throw new InvalidHeaderException('JWE protected header declares "zip"; compression is refused by default (RFC 8725 §3.6)');
        }
        if (array_key_exists('b64', $header)) {
            // `b64` (RFC 7797) is a JWS-only header with no meaning in a JWE.
            // Its presence signals confusion; refusing it keeps the fail-closed
            // posture consistent with `crit`/`zip` above.
            throw new InvalidHeaderException('JWE protected header declares "b64"; it is a JWS-only parameter (RFC 7797) and has no meaning in a JWE');
        }

        foreach (['typ', 'cty', 'kid'] as $optionalString) {
            if (array_key_exists($optionalString, $header) && !is_string($header[$optionalString])) {
                throw new InvalidHeaderException(sprintf('JWE protected header "%s" must be a string when present', $optionalString));
            }
        }
    }
}
