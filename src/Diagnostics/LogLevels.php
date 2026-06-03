<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Diagnostics;

use LogicException;
use Psr\Log\LogLevel;

/**
 * Maps each diagnostic event category this library emits to a PSR-3 log level.
 *
 * The library decides *which level* an event is emitted at; your PSR-3 logger
 * decides whether to record it. The defaults err quiet and security-focused —
 * accepted tokens and routine key cache hits at `debug`, policy rejections
 * (expired, wrong audience, …) at `notice`, and integrity failures (bad
 * signature, algorithm not allowed, decryption failure, JWKS fetch failure)
 * at `warning`.
 *
 * Override any subset with named arguments; the object is immutable:
 *
 * ```php
 * // Audit every accepted token, and treat claim rejections as warnings.
 * $levels = new LogLevels(accepted: LogLevel::INFO, claimRejected: LogLevel::WARNING);
 * ```
 *
 * Each value must be one of the eight PSR-3 level strings ({@see LogLevel});
 * an unknown level fails fast at construction.
 */
final class LogLevels
{
    /**
     * A token passed every check (signature/decryption + claims + profile).
     */
    public readonly string $accepted;

    /**
     * Signature, algorithm-allowlist, or key-resolution-on-verify failure —
     * an integrity problem, not a policy one.
     */
    public readonly string $verificationFailed;

    /**
     * A structurally valid, properly signed token whose claims fail the
     * validator's expectations (`exp`/`nbf`/`iat`/`iss`/`aud`/`sub`/`typ`,
     * a missing required claim, or a profile-specific rule).
     */
    public readonly string $claimRejected;

    /** A JWE was successfully decrypted and authenticated. */
    public readonly string $decrypted;

    /** JWE content decryption or key-unwrap failure. */
    public readonly string $decryptionFailed;

    /** Remote JWKS fetched, served from cache, or refreshed (operational). */
    public readonly string $keyResolution;

    /** Remote JWKS could not be fetched or parsed. */
    public readonly string $keyResolutionFailed;

    public function __construct(
        string $accepted = LogLevel::DEBUG,
        string $verificationFailed = LogLevel::WARNING,
        string $claimRejected = LogLevel::NOTICE,
        string $decrypted = LogLevel::DEBUG,
        string $decryptionFailed = LogLevel::WARNING,
        string $keyResolution = LogLevel::DEBUG,
        string $keyResolutionFailed = LogLevel::WARNING,
    ) {
        $this->accepted = self::assertLevel($accepted, 'accepted');
        $this->verificationFailed = self::assertLevel($verificationFailed, 'verificationFailed');
        $this->claimRejected = self::assertLevel($claimRejected, 'claimRejected');
        $this->decrypted = self::assertLevel($decrypted, 'decrypted');
        $this->decryptionFailed = self::assertLevel($decryptionFailed, 'decryptionFailed');
        $this->keyResolution = self::assertLevel($keyResolution, 'keyResolution');
        $this->keyResolutionFailed = self::assertLevel($keyResolutionFailed, 'keyResolutionFailed');
    }

    /**
     * The eight PSR-3 levels, lowest to highest severity.
     *
     * @return list<string>
     */
    public static function all(): array
    {
        return [
            LogLevel::DEBUG,
            LogLevel::INFO,
            LogLevel::NOTICE,
            LogLevel::WARNING,
            LogLevel::ERROR,
            LogLevel::CRITICAL,
            LogLevel::ALERT,
            LogLevel::EMERGENCY,
        ];
    }

    private static function assertLevel(string $level, string $category): string
    {
        if (!in_array($level, self::all(), true)) {
            throw new LogicException(sprintf(
                'Invalid PSR-3 log level "%s" for "%s"; expected one of: %s',
                $level,
                $category,
                implode(', ', self::all()),
            ));
        }

        return $level;
    }
}
