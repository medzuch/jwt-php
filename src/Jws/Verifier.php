<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Diagnostics\SecurityLog;
use Medzuch\Jwt\Exception\AlgorithmNotAllowedException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Medzuch\Jwt\Jws\Internal\B64Header;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyResolver;
use Medzuch\Jwt\Key\PublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use Psr\Log\LoggerInterface;

/**
 * Verifies the signature on a {@see ParsedJws}.
 *
 * Order of checks (each one fails closed with a typed exception before the
 * next runs):
 *
 *   1. **Header sanity.** The header is constrained to what this library
 *      understands. `crit` is refused unless it contains exactly the
 *      extensions the recipient supports — the only one this library
 *      supports is `"b64"` (RFC 7797). `b64:false` is only honoured when
 *      `crit` lists `"b64"`;
 *      both serializer and verifier enforce that, defence in depth.
 *      Anything else in `crit` (e.g. an unknown extension a peer chose to
 *      mark critical) is refused per RFC 7515 §4.1.11.
 *   2. **Algorithm allowlist** (RFC 8725 §3.1). The caller passes a list of
 *      `SigningAlgorithm` instances. The header's `alg` must match the
 *      `name()` of one of them. Any other value — including `none` (which
 *      no shipped allowlist contains) and lookalikes — is refused with
 *      {@see AlgorithmNotAllowedException}. This is the place where the
 *      library structurally refuses to let the token's header drive the
 *      verification strategy.
 *   3. **Key resolution.** The header (with `kid` if present) is handed to
 *      the {@see KeyResolver}. `jku` / `x5u` are not followed by default.
 *   4. **Crypto verify.** The selected algorithm runs its own
 *      `instanceof` + `assertAlgorithm` + `allowsOperation` checks and
 *      computes the signature comparison in constant time. A `false`
 *      return collapses to {@see SignatureVerificationException}.
 *
 * The verifier returns the {@see ParsedJws} unchanged on success; callers
 * who need the payload bytes read them from `$parsed->payload`. Returning
 * the same value type rather than a new "VerifiedJws" keeps the JWT layer
 * simple — it does its own payload parsing on the back of this.
 *
 * Two flavours:
 *   - {@see verify()} for the standard and embedded-payload forms (the
 *     middle segment of the compact form carries the payload, whether
 *     base64url-encoded or — under `b64:false` — raw).
 *   - {@see verifyDetached()} for the RFC 7515 Appendix F detached form
 *     where the middle segment is empty and the caller supplies the
 *     payload bytes out of band. The signing input is reconstructed from
 *     the caller's payload, honouring `b64`.
 */
final class Verifier
{
    private readonly ?SecurityLog $log;

    /**
     * @param ?LoggerInterface $logger optional PSR-3 sink; when set, each
     *                                 verify outcome is logged with a redacted
     *                                 context ({@see SecurityLog})
     */
    public function __construct(?LoggerInterface $logger = null, ?LogLevels $logLevels = null)
    {
        $this->log = $logger === null ? null : SecurityLog::for($logger, $logLevels);
    }

    /**
     * Note on empty payloads: an embedded JWS over a zero-length payload
     * serializes to an empty middle segment too (`Base64Url::encode('')`
     * is also `''`), so it is structurally indistinguishable from the
     * detached form at this layer. Callers signing an empty payload MUST
     * verify with {@see verifyDetached()} passing `''` — that fail-closed
     * branch is the price of compact-serialization ambiguity. Producers
     * that want to authenticate an empty payload without this ergonomic
     * quirk should use the detached form on the sign side as well.
     *
     * @param non-empty-list<SigningAlgorithm> $allowedAlgorithms strategies the caller is willing to accept
     *
     * @throws InvalidHeaderException        the JWS is structurally a detached form (empty middle)
     * @throws AlgorithmNotAllowedException
     * @throws SignatureVerificationException
     */
    public function verify(
        ParsedJws $jws,
        array $allowedAlgorithms,
        KeyResolver $keyResolver,
    ): ParsedJws {
        try {
            if ($jws->encodedPayload === '') {
                // The wire form had an empty middle segment: this is a detached
                // JWS (or an embedded zero-length payload, which collapses to
                // the same shape — see the docblock). The caller MUST use
                // verifyDetached() with the external payload. Falling through
                // here would verify the signature over `header.` — a different
                // signing input from the producer's — and either falsely fail
                // or, worse, mask an attack.
                throw new InvalidHeaderException('Detached JWS (empty payload segment); use Verifier::verifyDetached() with the external payload');
            }

            $verified = $this->verifyInternal($jws, $allowedAlgorithms, $keyResolver, $jws->encodedPayload);
        } catch (JwtException $e) {
            $this->log?->verificationFailed($e, self::headerKid($jws->header), self::headerAlg($jws->header));

            throw $e;
        }

        $this->log?->tokenAccepted(self::headerKid($jws->header), self::headerAlg($jws->header));

        return $verified;
    }

    /**
     * Verify a detached JWS (RFC 7515 Appendix F): the on-the-wire compact
     * form has an empty payload segment, and the caller delivers the raw
     * payload bytes here. The signing input is reconstructed honouring the
     * header's `b64` mode — raw bytes when `b64:false`, base64url-encoded
     * otherwise — so the same producer can be verified with either flag.
     *
     * @param non-empty-list<SigningAlgorithm> $allowedAlgorithms
     *
     * @throws InvalidHeaderException        the JWS is not actually detached (non-empty middle)
     * @throws MalformedJwtException
     * @throws AlgorithmNotAllowedException
     * @throws SignatureVerificationException
     */
    public function verifyDetached(
        ParsedJws $jws,
        string $payload,
        array $allowedAlgorithms,
        KeyResolver $keyResolver,
    ): ParsedJws {
        try {
            if ($jws->encodedPayload !== '') {
                // Symmetric to verify(): refuse the wrong shape so a caller who
                // confused the two methods finds out at the boundary.
                throw new InvalidHeaderException('JWS is not detached (payload segment is non-empty); use Verifier::verify()');
            }

            $b64 = self::b64Mode($jws->header);
            $encodedPayload = $b64 === false ? $payload : Base64Url::encode($payload);

            // Mutate is not an option — ParsedJws is readonly. Build a new
            // value with the reconstructed payload so the algorithm strategy
            // sees a consistent picture, and so callers downstream can read
            // `payload` without having to remember whether they supplied it.
            $jws = new ParsedJws(
                $jws->encodedHeader,
                $jws->encodedPayload,
                $jws->encodedSignature,
                $jws->header,
                $payload,
                $jws->signature,
            );

            $verified = $this->verifyInternal($jws, $allowedAlgorithms, $keyResolver, $encodedPayload);
        } catch (JwtException $e) {
            $this->log?->verificationFailed($e, self::headerKid($jws->header), self::headerAlg($jws->header));

            throw $e;
        }

        $this->log?->tokenAccepted(self::headerKid($jws->header), self::headerAlg($jws->header));

        return $verified;
    }

    /**
     * @param non-empty-list<SigningAlgorithm> $allowedAlgorithms
     *
     * @throws AlgorithmNotAllowedException
     * @throws InvalidHeaderException
     * @throws SignatureVerificationException
     */
    private function verifyInternal(
        ParsedJws $jws,
        array $allowedAlgorithms,
        KeyResolver $keyResolver,
        string $encodedPayloadForSigningInput,
    ): ParsedJws {
        // CompactSerializer::deserialize() already ran the same validation;
        // this is defence in depth for ParsedJws values built another way.
        B64Header::assertValid($jws->header);

        $alg = $jws->header['alg'] ?? null;
        if (!is_string($alg) || $alg === '') {
            // CompactSerializer::deserialize() already enforces this; the
            // re-check is defence in depth in case a ParsedJws is built
            // through another path in future code.
            throw new InvalidHeaderException('Protected header is missing a usable "alg"');
        }

        $algorithm = self::selectAlgorithm($alg, $allowedAlgorithms);

        $key = $keyResolver->resolve($jws->header);

        $signingInput = $jws->encodedHeader . '.' . $encodedPayloadForSigningInput;

        // The algorithm strategy is what actually narrows the key to the
        // right class (HmacKey vs RsaPublicKey vs ...). This is the third
        // McLean barrier: even if the allowlist were permissive and the
        // resolver returned the wrong key kind, Hs256::verify on an
        // RsaPublicKey throws KeyMismatchException before any crypto runs.
        if (!$algorithm->verify($signingInput, $jws->signature, self::asPublicKey($key))) {
            throw new SignatureVerificationException(sprintf('Signature did not verify under algorithm %s', $alg));
        }

        return $jws;
    }

    /**
     * @param array<string, mixed> $header
     *
     * @throws InvalidHeaderException
     */
    private static function b64Mode(array $header): ?bool
    {
        $value = $header['b64'] ?? null;

        return is_bool($value) ? $value : null;
    }

    /** @param array<string, mixed> $header */
    private static function headerKid(array $header): ?string
    {
        $kid = $header['kid'] ?? null;

        return is_string($kid) ? $kid : null;
    }

    /** @param array<string, mixed> $header */
    private static function headerAlg(array $header): ?string
    {
        $alg = $header['alg'] ?? null;

        return is_string($alg) ? $alg : null;
    }

    /**
     * @param non-empty-list<SigningAlgorithm> $allowed
     *
     * @throws AlgorithmNotAllowedException
     */
    private static function selectAlgorithm(string $algName, array $allowed): SigningAlgorithm
    {
        foreach ($allowed as $candidate) {
            if ($candidate->name() === $algName) {
                return $candidate;
            }
        }

        $allowedNames = array_map(static fn(SigningAlgorithm $a): string => $a->name(), $allowed);

        throw new AlgorithmNotAllowedException(sprintf('Algorithm "%s" is not in the allowlist [%s] (RFC 8725 §3.1)', $algName, implode(', ', $allowedNames)));
    }

    private static function asPublicKey(Key $key): PublicKey
    {
        if (!$key instanceof PublicKey) {
            // A resolver that returns a private-only key on the verify
            // path is misconfigured — surface it as a header problem so
            // the operator sees it in logs.
            throw new InvalidHeaderException(sprintf('Resolved key is not usable for verification (%s)', $key::class));
        }

        return $key;
    }
}
