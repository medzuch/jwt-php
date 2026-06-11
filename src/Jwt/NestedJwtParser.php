<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jwe\CompactSerializer as JweCompactSerializer;
use Medzuch\Jwt\Jwe\Decrypter;
use Medzuch\Jwt\Jwe\JsonSerializer as JweJsonSerializer;
use Medzuch\Jwt\Jwe\ParsedJwe;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\KeyResolver;
use Psr\Log\LoggerInterface;

/**
 * Consumer counterpart to {@see NestedJwtBuilder}: parses a nested JWT —
 * a JWE that wraps a signed JWS that carries a JWT Claims Set
 * (RFC 7519 §5.2) — and returns a structurally sound, signature-verified
 * {@see NestedJwt} or throws a typed exception.
 *
 * The parse is decrypt-then-verify, matching producer-side sign-then-encrypt
 * (T4): the inner JWS bytes never exist in cleartext until the outer JWE
 * has authenticated them via its AEAD tag, and the inner signature is then
 * verified against the caller's signing-algorithm allowlist before any
 * caller sees the claims.
 *
 * Order of operations, each step fails closed before the next runs:
 *
 *   1. **Outer parse.** The input is sniffed as compact (five dot-separated
 *      base64url segments) or JSON, and routed to the matching JWE
 *      serializer. Both refuse `crit`/`zip`/`b64` and missing `alg`/`enc`.
 *   2. **Decrypt.** {@see Decrypter} runs the JWE allowlists for `alg`/`enc`,
 *      resolves the key, recovers the CEK, and authenticates+decrypts.
 *   3. **`cty` enforcement.** RFC 7519 §5.2 requires `cty: "JWT"` in the
 *      outer header for nested JWTs. Absence or any other value is refused
 *      here, before the plaintext is treated as a JWS, so a token whose
 *      plaintext happens to look like compact JWS but was not intended as
 *      a nested JWT cannot be admitted.
 *   4. **Inner parse + verify.** The plaintext is parsed by
 *      {@see JwtParser} (which itself rejects `b64` in JWT headers) and the
 *      inner JWS is verified by {@see Verifier} under the caller's signing
 *      allowlist.
 *   5. **Replication consistency (RFC 7519 §5.3).** For every claim name
 *      present in *both* the outer JOSE header and the inner Claims Set,
 *      the values must be equal. Mismatches are refused — the spec mandates
 *      it ("Receivers MUST reject JWTs in which the replicated values are
 *      not consistent"). Names present in only one side are not constrained
 *      and not checked.
 *
 * The result is two-phase like {@see JwtParser}: this returns a
 * {@see NestedJwt}, and the caller hands its `inner` to {@see Validator}
 * to enforce `iss`/`aud`/`exp`/... — exactly the same way they would after
 * {@see JwtParser::parse()}. The split keeps the validation language one
 * thing across the codebase.
 */
final class NestedJwtParser
{
    /**
     * JOSE header parameter names registered by RFC 7515 §4.1 (JWS),
     * RFC 7516 §4.1 (JWE — including AES-KW `iv`/`tag`, ECDH-ES `epk`/`apu`/`apv`,
     * PBES2 `p2s`/`p2c`), and RFC 7797 §3 (`b64`). These are *structural*
     * outer-header members — protocol metadata that drives routing or
     * decryption — and are deliberately not subject to the RFC 7519 §5.3
     * replicated-claim consistency check. A custom JWT claim with the same
     * name (e.g. an inner `kid` claim) belongs to a different namespace and
     * is unrelated to the outer `kid` header parameter.
     */
    private const JOSE_HEADER_PARAMETERS = [
        'alg', 'enc', 'zip',
        'jku', 'jwk', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256',
        'typ', 'cty', 'crit',
        'epk', 'apu', 'apv', 'iv', 'tag', 'p2s', 'p2c',
        'b64',
    ];

    /**
     * @param ?LoggerInterface $logger optional PSR-3 sink, threaded to the
     *                                 inner {@see Decrypter} and {@see Verifier}
     *                                 so the JWE-decrypt and inner-JWS-verify
     *                                 outcomes are logged. The subsequent
     *                                 {@see Validator::validate()} on the inner
     *                                 token is the caller's own (separately
     *                                 logged) step.
     */
    public function __construct(
        private readonly ?LoggerInterface $logger = null,
        private readonly ?LogLevels $logLevels = null,
    ) {}

    /**
     * @param non-empty-list<KeyManagementAlgorithm>     $allowedKeyManagement     accepted outer `alg`
     * @param non-empty-list<ContentEncryptionAlgorithm> $allowedContentEncryption accepted outer `enc`
     * @param non-empty-list<SigningAlgorithm>           $allowedSigningAlgorithms accepted inner `alg`
     *
     * @throws MalformedJwtException                                       structural problem at any layer
     * @throws InvalidHeaderException                                      `cty` missing or not `"JWT"`, or a §5.3 mismatch
     * @throws \Medzuch\Jwt\Exception\AlgorithmNotAllowedException
     * @throws \Medzuch\Jwt\Exception\KeyNotFoundException
     * @throws \Medzuch\Jwt\Exception\KeyMismatchException
     * @throws \Medzuch\Jwt\Exception\DecryptionException
     * @throws \Medzuch\Jwt\Exception\SignatureVerificationException
     */
    public function parse(
        string $compact,
        array $allowedKeyManagement,
        array $allowedContentEncryption,
        KeyResolver $decryptionKeyResolver,
        array $allowedSigningAlgorithms,
        KeyResolver $verificationKeyResolver,
    ): NestedJwt {
        $outerJwe = self::parseOuter($compact);

        $innerCompact = (new Decrypter($this->logger, $this->logLevels))->decrypt(
            $outerJwe,
            $allowedKeyManagement,
            $allowedContentEncryption,
            $decryptionKeyResolver,
        );

        self::assertNestedContentType($outerJwe->header);

        $inner = JwtParser::parse($innerCompact);

        (new Verifier($this->logger, $this->logLevels))->verify($inner->jws, $allowedSigningAlgorithms, $verificationKeyResolver);

        self::assertReplicatedClaimsConsistent($outerJwe->header, $inner->unverifiedClaims->all());

        return new NestedJwt($outerJwe->header, $inner);
    }

    /**
     * Sniff compact vs. JSON. A compact JWE is exactly five
     * dot-separated base64url segments (RFC 7516 §7.1); anything starting
     * with `{` goes through the JSON serializer.
     *
     * @throws MalformedJwtException
     * @throws InvalidHeaderException
     */
    private static function parseOuter(string $compact): ParsedJwe
    {
        $trimmed = ltrim($compact);
        if ($trimmed !== '' && $trimmed[0] === '{') {
            return JweJsonSerializer::deserialize($compact);
        }

        return JweCompactSerializer::deserialize($compact);
    }

    /**
     * @param array<string, mixed> $outerHeader
     *
     * @throws InvalidHeaderException
     */
    private static function assertNestedContentType(array $outerHeader): void
    {
        $cty = $outerHeader['cty'] ?? null;
        if ($cty === null) {
            throw new InvalidHeaderException('Nested JWT outer header must declare "cty": "JWT" (RFC 7519 §5.2)');
        }
        // RFC 7515 §4.1.9: media types omit the `application/` prefix on the
        // wire and the comparison is case-insensitive, so `application/jwt`
        // and `JWT` are equivalent. Delegate to the same normaliser the
        // {@see \Medzuch\Jwt\Jwt\Validator} uses for `typ`.
        if (!is_string($cty) || !MediaType::equivalent($cty, 'JWT')) {
            throw new InvalidHeaderException(sprintf('Nested JWT outer header "cty" must be "JWT" (RFC 7519 §5.2); got %s', self::describe($cty)));
        }
    }

    /**
     * RFC 7519 §5.3: "If such replicated claims are present, the values of
     * those Header Parameters MUST be the same as those of the corresponding
     * Claims in the JWT Claims Set, after decryption. Receivers MUST reject
     * JWTs in which the replicated values are not consistent."
     *
     * Equality is by value identity (`===`) — `iss` is a string, `aud` may
     * be a string or list of strings, so both arms collapse to PHP's deep
     * comparison without coercion. We do NOT canonicalise (no reordering
     * of list members, no case folding): the producer chose the inner
     * shape and the replicated header value has to match it exactly.
     *
     * @param array<string, mixed> $outerHeader
     * @param array<string, mixed> $innerClaims
     *
     * @throws InvalidHeaderException
     */
    private static function assertReplicatedClaimsConsistent(array $outerHeader, array $innerClaims): void
    {
        foreach (array_intersect_key($outerHeader, $innerClaims) as $name => $headerValue) {
            // JOSE header parameter names are structural protocol metadata
            // (routing, decryption inputs, content typing) — they share a
            // namespace with JWT claims only by coincidence. §5.3 is about
            // claims *deliberately replicated* into the header; a custom
            // claim that happens to be named `kid` is unrelated to the
            // outer `kid` header parameter and must not be compared. The
            // intersection check therefore filters JOSE param names out.
            if (in_array($name, self::JOSE_HEADER_PARAMETERS, true)) {
                continue;
            }
            if ($headerValue !== $innerClaims[$name]) {
                throw new InvalidHeaderException(sprintf('Nested JWT replicated claim "%s" disagrees between outer header and inner Claims Set (RFC 7519 §5.3)', $name));
            }
        }
    }

    /** @infection-ignore-all — diagnostic helper: builds words for exception messages only. */
    private static function describe(mixed $value): string
    {
        return match (true) {
            $value === null => 'null',
            is_string($value) => '"' . $value . '"',
            default => '(' . get_debug_type($value) . ')',
        };
    }
}
