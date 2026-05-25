<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm;

/**
 * The four key-management modes of RFC 7518 §2, minus Key Encryption.
 *
 * The mode tells the {@see \Medzuch\Jwt\Jwe\Encrypter} / Decrypter how the
 * Content Encryption Key relates to the recipient key, and therefore what
 * the JWE Encrypted Key segment and the per-recipient header parameters look
 * like:
 *
 *   - {@see self::DirectEncryption} — the shared symmetric key *is* the CEK
 *     (`dir`). The Encrypted Key segment is empty.
 *   - {@see self::KeyWrapping} — a fresh random CEK is wrapped with a
 *     symmetric KEK (A\*KW, A\*GCMKW). The wrapped CEK is the Encrypted Key.
 *   - {@see self::DirectKeyAgreement} — the CEK is derived from an ECDH-ES
 *     agreement (`ECDH-ES`); the ephemeral public key travels in `epk`. The
 *     Encrypted Key segment is empty.
 *   - {@see self::KeyAgreementWithKeyWrapping} — ECDH-ES derives a KEK that
 *     then wraps a fresh random CEK (`ECDH-ES+A*KW`).
 *
 * Key Encryption (RSA-OAEP / RSA1_5) is deliberately omitted: all RSA-based
 * JWE is deferred out of v0.3 (docs/12-decisions.md, D-003).
 */
enum KeyManagementMode
{
    case DirectEncryption;
    case KeyWrapping;
    case DirectKeyAgreement;
    case KeyAgreementWithKeyWrapping;
}
