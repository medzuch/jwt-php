<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe;

use Medzuch\Jwt\Algorithm\Algorithm;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Diagnostics\SecurityLog;
use Medzuch\Jwt\Exception\AlgorithmNotAllowedException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Key\KeyResolver;
use Psr\Log\LoggerInterface;

/**
 * Decrypts and authenticates a {@see ParsedJwe}, returning the plaintext.
 *
 * The JWE counterpart to {@see \Medzuch\Jwt\Jws\Verifier}, with the same
 * fail-closed, allowlist-driven posture (each step throws a typed exception
 * before the next runs):
 *
 *   1. **Algorithm allowlists** (RFC 8725 §3.1). The caller passes the
 *      `alg` (key-management) and `enc` (content-encryption) algorithms it
 *      is willing to accept. The header's `alg`/`enc` must each match one by
 *      `name()`; anything else — including unknown or `none`-like values —
 *      is refused with {@see AlgorithmNotAllowedException}. The token's
 *      header never drives algorithm selection.
 *   2. **Key resolution.** The header (with `kid` if present) is handed to
 *      the {@see KeyResolver}. `jku`/`x5u` are not followed by default.
 *   3. **CEK recovery.** The key-management algorithm narrows the resolved
 *      key to the right class and recovers the Content Encryption Key.
 *   4. **Authenticated decryption.** The content algorithm authenticates the
 *      AAD (the on-the-wire encoded header) and tag, then decrypts. Any
 *      failure collapses to {@see \Medzuch\Jwt\Exception\DecryptionException}.
 *
 * Structural refusals (`crit`, `zip`, `b64`, missing `alg`/`enc`) have
 * already happened in {@see CompactSerializer::deserialize()}.
 */
final class Decrypter
{
    private readonly ?SecurityLog $log;

    public function __construct(?LoggerInterface $logger = null, ?LogLevels $logLevels = null)
    {
        $this->log = $logger === null ? null : SecurityLog::for($logger, $logLevels);
    }

    /**
     * @param non-empty-list<KeyManagementAlgorithm>     $allowedKeyManagement     accepted `alg` strategies
     * @param non-empty-list<ContentEncryptionAlgorithm> $allowedContentEncryption accepted `enc` strategies
     *
     * @throws AlgorithmNotAllowedException
     * @throws InvalidHeaderException
     * @throws \Medzuch\Jwt\Exception\KeyNotFoundException
     * @throws \Medzuch\Jwt\Exception\KeyMismatchException
     * @throws \Medzuch\Jwt\Exception\DecryptionException
     */
    public function decrypt(
        ParsedJwe $jwe,
        array $allowedKeyManagement,
        array $allowedContentEncryption,
        KeyResolver $keyResolver,
    ): string {
        $kid = self::headerString($jwe->header, 'kid');
        $alg = self::headerString($jwe->header, 'alg');
        $enc = self::headerString($jwe->header, 'enc');

        try {
            $plaintext = $this->decryptInternal($jwe, $allowedKeyManagement, $allowedContentEncryption, $keyResolver);
        } catch (JwtException $e) {
            $this->log?->decryptionFailed($e, $kid, $alg, $enc);

            throw $e;
        }

        $this->log?->tokenDecrypted($kid, $alg, $enc);

        return $plaintext;
    }

    /**
     * @param non-empty-list<KeyManagementAlgorithm>     $allowedKeyManagement
     * @param non-empty-list<ContentEncryptionAlgorithm> $allowedContentEncryption
     */
    private function decryptInternal(
        ParsedJwe $jwe,
        array $allowedKeyManagement,
        array $allowedContentEncryption,
        KeyResolver $keyResolver,
    ): string {
        $alg = $jwe->header['alg'] ?? null;
        $enc = $jwe->header['enc'] ?? null;
        if (!is_string($alg) || $alg === '' || !is_string($enc) || $enc === '') {
            // CompactSerializer::deserialize() already enforces both; the
            // re-check is defence in depth for a ParsedJwe built elsewhere.
            throw new InvalidHeaderException('JWE protected header is missing a usable "alg"/"enc"');
        }

        $keyManagement = self::selectByName($alg, $allowedKeyManagement, 'alg');
        $contentEncryption = self::selectByName($enc, $allowedContentEncryption, 'enc');

        $key = $keyResolver->resolve($jwe->header);

        $cek = $keyManagement->decryptKey($key, $contentEncryption, $jwe->encryptedKey, $jwe->header);

        return $contentEncryption->decrypt(
            $jwe->ciphertext,
            $cek,
            $jwe->iv,
            $jwe->tag,
            $jwe->additionalAuthenticatedData(),
        );
    }

    /** @param array<string, mixed> $header */
    private static function headerString(array $header, string $key): ?string
    {
        $value = $header[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * @template TAlgo of Algorithm
     *
     * @param non-empty-list<TAlgo> $allowed
     *
     * @return TAlgo
     *
     * @throws AlgorithmNotAllowedException
     */
    private static function selectByName(string $name, array $allowed, string $headerParam): Algorithm
    {
        foreach ($allowed as $candidate) {
            if ($candidate->name() === $name) {
                return $candidate;
            }
        }

        $names = array_map(static fn(Algorithm $a): string => $a->name(), $allowed);

        throw new AlgorithmNotAllowedException(sprintf('%s "%s" is not in the allowlist [%s] (RFC 8725 §3.1)', $headerParam, $name, implode(', ', $names)));
    }
}
