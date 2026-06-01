<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

use RuntimeException;

/**
 * A JWE could not be decrypted or authenticated.
 *
 * Raised whenever the encryption layer fails closed: an unwrappable
 * Content Encryption Key, a content-integrity (AEAD tag / HMAC) mismatch,
 * a malformed or rejected ephemeral key (`epk`) on an ECDH-ES token, or a
 * crypto-backend error during decryption. Like
 * {@see SignatureVerificationException} on the JWS side, this is the single
 * typed failure callers catch for "the ciphertext did not check out" —
 * the message never leaks plaintext or key material.
 */
final class DecryptionException extends RuntimeException implements JwtException {}
