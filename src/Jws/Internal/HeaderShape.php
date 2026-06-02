<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws\Internal;

use Medzuch\Jwt\Exception\InvalidHeaderException;

/**
 * Shared shape checks for the integrity-protected JOSE header. Both the
 * compact and JSON deserializers must enforce these so the algorithm and
 * the typed string members that drive downstream decisions are always
 * carried in the integrity-protected segment — not in an unauthenticated
 * `header` member where an attacker could pick them.
 *
 * Rules:
 *
 *   1. `alg` MUST be present in the protected header (RFC 7515 §4.1.1).
 *      Algorithm selection MUST be driven by an integrity-protected value
 *      (RFC 8725 §3.1).
 *   2. `alg` MUST be a non-empty string.
 *   3. `typ`, `cty`, `kid` (when present) MUST be strings. Presence checks
 *      use `array_key_exists`, not `isset`, so an explicit JSON `null`
 *      fails here rather than being silently treated as absent.
 *
 * `crit`/`b64` shape is enforced separately by {@see B64Header::assertValid}
 * so the RFC 7797 + §4.1.11 coupling lives in one place.
 */
final class HeaderShape
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * @param array<string, mixed> $header
     *
     * @throws InvalidHeaderException
     */
    public static function assertProtected(array $header): void
    {
        if (!array_key_exists('alg', $header)) {
            throw new InvalidHeaderException('Protected header is missing required "alg"');
        }
        if (!is_string($header['alg']) || $header['alg'] === '') {
            throw new InvalidHeaderException('Protected header "alg" must be a non-empty string');
        }

        if (array_key_exists('typ', $header) && !is_string($header['typ'])) {
            throw new InvalidHeaderException('Protected header "typ" must be a string when present');
        }
        if (array_key_exists('cty', $header) && !is_string($header['cty'])) {
            throw new InvalidHeaderException('Protected header "cty" must be a string when present');
        }
        if (array_key_exists('kid', $header) && !is_string($header['kid'])) {
            throw new InvalidHeaderException('Protected header "kid" must be a string when present');
        }
    }
}
