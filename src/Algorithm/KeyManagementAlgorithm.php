<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm;

/**
 * Marker contract for JWE key-management (`alg`) algorithms — the schemes
 * that establish the Content Encryption Key between sender and recipient
 * (RFC 7518 §4).
 *
 * Key management is far less uniform than signing: `dir` ships no Encrypted
 * Key at all, AES key-wrapping transports a wrapped CEK, and ECDH-ES derives
 * one from a key agreement while adding an `epk` header. Rather than force
 * all of those through one awkward signature, the concrete operations
 * (wrap/unwrap a CEK, derive a CEK from an agreement) live on focused
 * sub-interfaces introduced alongside the algorithms that implement them —
 * AES key-wrapping in its PR, ECDH-ES in its own. This interface is the
 * common type the {@see \Medzuch\Jwt\Jwe\Encrypter} / Decrypter hold an
 * allowlist of, and {@see self::mode()} is how they dispatch to the right
 * path without inspecting concrete classes.
 *
 * RSA key encryption (RSA-OAEP, RSA1_5) is not modelled: it is deferred out
 * of v0.3 (docs/12-decisions.md, D-003).
 */
interface KeyManagementAlgorithm extends Algorithm
{
    /**
     * Which RFC 7518 §2 mode this algorithm follows, so the Encrypter knows
     * whether to expect an empty Encrypted Key, a wrapped CEK, or an
     * agreement-derived key.
     */
    public function mode(): KeyManagementMode;
}
