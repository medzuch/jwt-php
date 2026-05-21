<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jws;

use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\AlgorithmNotAllowedException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyResolver;
use Medzuch\Jwt\Key\PublicKey;

/**
 * Verifies the signature on a {@see ParsedJws}.
 *
 * Order of checks (each one fails closed with a typed exception before the
 * next runs):
 *
 *   1. **Header sanity.** `crit` is refused outright — RFC 7515 §4.1.11
 *      requires the receiver to reject a JWS whose `crit` contains anything
 *      it does not understand, and Phase 1 understands no extensions.
 *      `b64:false` is refused — its support belongs to Phase 4 and the JWT
 *      profile MUST refuse it (RFC 7797 §7).
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
 *      `instanceof` + `assertAlgorithm` + `allowsOperation` checks
 *      (Layer 3 from PR #3) and computes the signature comparison in
 *      constant time. A `false` return collapses to
 *      {@see SignatureVerificationException}.
 *
 * The verifier returns the {@see ParsedJws} unchanged on success; callers
 * who need the payload bytes read them from `$parsed->payload`. Returning
 * the same value type rather than a new "VerifiedJws" keeps the JWT layer
 * (PR #5) simple — it does its own payload parsing on the back of this.
 */
final class Verifier
{
    /**
     * @param non-empty-list<SigningAlgorithm> $allowedAlgorithms strategies the caller is willing to accept
     */
    public function verify(
        ParsedJws $jws,
        array $allowedAlgorithms,
        KeyResolver $keyResolver,
    ): ParsedJws {
        self::assertSupportedHeader($jws->header);

        $alg = $jws->header['alg'] ?? null;
        if (!is_string($alg) || $alg === '') {
            // CompactSerializer::deserialize() already enforces this; the
            // re-check is defence in depth in case a ParsedJws is built
            // through another path in future code.
            throw new InvalidHeaderException('Protected header is missing a usable "alg"');
        }

        $algorithm = self::selectAlgorithm($alg, $allowedAlgorithms);

        $key = $keyResolver->resolve($jws->header);

        // The algorithm strategy is what actually narrows the key to the
        // right class (HmacKey vs RsaPublicKey vs ...). This is the third
        // McLean barrier: even if the allowlist were permissive and the
        // resolver returned the wrong key kind, Hs256::verify on an
        // RsaPublicKey throws KeyMismatchException before any crypto runs.
        if (!$algorithm->verify($jws->signingInput(), $jws->signature, self::asPublicKey($key))) {
            throw new SignatureVerificationException(sprintf('Signature did not verify under algorithm %s', $alg));
        }

        return $jws;
    }

    /**
     * @param array<string, mixed> $header
     *
     * @throws InvalidHeaderException
     */
    private static function assertSupportedHeader(array $header): void
    {
        // `array_key_exists`, not `isset`: a header that declares `crit`
        // or `b64` with an explicit JSON `null` must be refused too. The
        // rule is "the parameter is forbidden in Phase 1 regardless of
        // value"; `isset` would have treated `null` as if the parameter
        // were absent and let the token through.
        if (array_key_exists('crit', $header)) {
            throw new InvalidHeaderException('Protected header declares "crit" extensions; this library understands none and RFC 7515 §4.1.11 requires refusal');
        }

        if (array_key_exists('b64', $header)) {
            // RFC 7797 introduces `b64`. The JWS layer in Phase 4 will
            // accept it explicitly; until then, refuse so that an
            // unpadded payload cannot be smuggled past us.
            throw new InvalidHeaderException('Protected header declares "b64" (RFC 7797); not supported until Phase 4 and forbidden in JWTs');
        }
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
