<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Diagnostics;

use Medzuch\Jwt\Exception\ExpiredException;
use Medzuch\Jwt\Exception\InvalidAudienceException;
use Medzuch\Jwt\Exception\InvalidIssuerException;
use Medzuch\Jwt\Exception\InvalidSubjectException;
use Medzuch\Jwt\Exception\InvalidTypeException;
use Medzuch\Jwt\Exception\IssuedInFutureException;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Exception\NotYetValidException;
use Psr\Log\LoggerInterface;

/**
 * @internal The single place the library emits diagnostic events, and the
 * single place the redaction policy is enforced.
 *
 * Every public consume/verify/decrypt/resolve entry point builds one of these
 * from an optional {@see LoggerInterface} and a {@see LogLevels} map, then
 * calls the semantic methods below. When no logger is configured every method
 * is a cheap no-op.
 *
 * **Redaction contract.** Only a fixed allowlist of non-sensitive fields is
 * ever emitted — `kid`, `alg`, `enc`, `typ`, `profile`, the failing `claim`
 * *name*, the `reason` (exception short-class), and the configured `jwks_uri`
 * / cache `source`. Tokens, payloads, claim *values*, key material, and raw
 * exception messages (which can embed values) are never logged. The
 * {@see emit()} sink filters context against {@see CONTEXT_ALLOWLIST} as a
 * second barrier, so a future caller cannot accidentally widen the surface.
 */
final class SecurityLog
{
    /**
     * The only context keys that may reach the logger. Anything else is
     * dropped by {@see emit()}.
     */
    private const CONTEXT_ALLOWLIST = [
        'kid', 'alg', 'enc', 'typ', 'profile', 'claim', 'reason', 'jwks_uri', 'source',
    ];

    /**
     * Exception type → the claim name it concerns. Lets us name the failing
     * claim without parsing (and re-leaking) the exception message.
     *
     * @var array<class-string, string>
     */
    private const CLAIM_BY_EXCEPTION = [
        ExpiredException::class => 'exp',
        NotYetValidException::class => 'nbf',
        IssuedInFutureException::class => 'iat',
        InvalidIssuerException::class => 'iss',
        InvalidAudienceException::class => 'aud',
        InvalidSubjectException::class => 'sub',
        InvalidTypeException::class => 'typ',
    ];

    private function __construct(
        private readonly ?LoggerInterface $logger,
        private readonly LogLevels $levels,
    ) {}

    /**
     * Build a logger sink. A null logger yields a no-op instance; a null
     * level map uses the secure defaults.
     */
    public static function for(?LoggerInterface $logger, ?LogLevels $levels): self
    {
        return new self($logger, $levels ?? new LogLevels());
    }

    public function tokenAccepted(?string $kid, ?string $alg, ?string $typ = null, ?string $profile = null): void
    {
        $this->emit($this->levels->accepted, 'JWT accepted', [
            'kid' => $kid,
            'alg' => $alg,
            'typ' => $typ,
            'profile' => $profile,
        ]);
    }

    public function verificationFailed(JwtException $e, ?string $kid, ?string $alg, ?string $profile = null): void
    {
        $this->emit($this->levels->verificationFailed, 'JWT signature verification failed', [
            'kid' => $kid,
            'alg' => $alg,
            'profile' => $profile,
            'reason' => self::shortName($e),
        ]);
    }

    public function claimRejected(JwtException $e, ?string $kid = null, ?string $alg = null, ?string $profile = null): void
    {
        $this->emit($this->levels->claimRejected, 'JWT claim rejected', [
            'kid' => $kid,
            'alg' => $alg,
            'profile' => $profile,
            'claim' => self::CLAIM_BY_EXCEPTION[$e::class] ?? null,
            'reason' => self::shortName($e),
        ]);
    }

    public function tokenDecrypted(?string $kid, ?string $alg, ?string $enc): void
    {
        $this->emit($this->levels->decrypted, 'JWE decrypted', [
            'kid' => $kid,
            'alg' => $alg,
            'enc' => $enc,
        ]);
    }

    public function decryptionFailed(JwtException $e, ?string $kid, ?string $alg, ?string $enc): void
    {
        $this->emit($this->levels->decryptionFailed, 'JWE decryption failed', [
            'kid' => $kid,
            'alg' => $alg,
            'enc' => $enc,
            'reason' => self::shortName($e),
        ]);
    }

    /**
     * @param 'network'|'cache' $source where the key set came from
     */
    public function keyResolved(string $jwksUri, string $source): void
    {
        $this->emit($this->levels->keyResolution, 'JWKS resolved', [
            'jwks_uri' => $jwksUri,
            'source' => $source,
        ]);
    }

    public function keyResolutionFailed(JwtException $e, string $jwksUri): void
    {
        $this->emit($this->levels->keyResolutionFailed, 'JWKS resolution failed', [
            'jwks_uri' => $jwksUri,
            'reason' => self::shortName($e),
        ]);
    }

    /**
     * @param array<string, string|null> $context
     */
    private function emit(string $level, string $message, array $context): void
    {
        if ($this->logger === null) {
            return;
        }

        $safe = [];
        foreach ($context as $key => $value) {
            if ($value !== null && in_array($key, self::CONTEXT_ALLOWLIST, true)) {
                $safe[$key] = $value;
            }
        }

        $this->logger->log($level, $message, $safe);
    }

    private static function shortName(JwtException $e): string
    {
        $class = $e::class;
        $pos = strrpos($class, '\\');

        return $pos === false ? $class : substr($class, $pos + 1);
    }
}
