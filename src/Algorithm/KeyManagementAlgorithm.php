<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm;

use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\Key;

/**
 * Contract for JWE key-management (`alg`) algorithms — the schemes that
 * establish the Content Encryption Key between sender and recipient
 * (RFC 7518 §4).
 *
 * Key management is far less uniform than signing — `dir` ships no Encrypted
 * Key, AES key-wrapping transports a wrapped CEK, ECDH-ES derives one from a
 * key agreement and adds an `epk` header — but all of it reduces to the same
 * two operations the {@see \Medzuch\Jwt\Jwe\Encrypter} / Decrypter need:
 * produce a CEK (plus whatever Encrypted Key and header parameters the scheme
 * requires) for encryption, and recover the CEK for decryption.
 * {@see self::mode()} lets callers reason about the scheme without inspecting
 * concrete classes.
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

    /**
     * Establish a CEK for encrypting to `$recipientKey` under the chosen
     * content-encryption algorithm, returning the CEK, the JWE Encrypted Key
     * octets, and any header parameters this scheme contributes.
     *
     * @throws KeyMismatchException if `$recipientKey` is the wrong kind/binding for this algorithm
     * @throws DecryptionException  if the underlying key operation fails
     */
    public function encryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption): CekEncryptionResult;

    /**
     * Recover the CEK for decryption from the JWE Encrypted Key and the
     * protected header (which carries per-recipient parameters such as `epk`,
     * `iv`, and `tag` where the scheme uses them).
     *
     * @param array<string, mixed> $header the decoded JWE Protected Header
     *
     * @return non-empty-string the recovered Content Encryption Key
     *
     * @throws KeyMismatchException if `$recipientKey` is the wrong kind/binding for this algorithm
     * @throws DecryptionException  if the CEK cannot be recovered
     */
    public function decryptKey(Key $recipientKey, ContentEncryptionAlgorithm $contentEncryption, string $encryptedKey, array $header): string;
}
