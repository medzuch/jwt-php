<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\Random;

/**
 * Produces a JWE from a plaintext, a protected header, a key-management
 * algorithm, a content-encryption algorithm, and the recipient key (RFC 7516
 * §5.1), in any of the three serializations: compact ({@see self::encrypt()}),
 * flattened JSON ({@see self::encryptFlattened()}), and general JSON
 * ({@see self::encryptGeneral()}).
 *
 * The JWE counterpart to {@see \Medzuch\Jwt\Jws\Signer}, and intentionally
 * thin in the same way — it composes pieces the algorithm layer has already
 * validated:
 *
 *   1. Forces `alg` / `enc` in the header to match the chosen algorithms (a
 *      caller-supplied value that disagrees is a programming error worth
 *      surfacing, exactly as {@see \Medzuch\Jwt\Jws\Signer} treats `alg`).
 *   2. Asks the key-management algorithm to establish the CEK, yielding the
 *      JWE Encrypted Key and any per-recipient header parameters (e.g. `epk`).
 *      Those parameters go into the **protected** header, so they are
 *      authenticated.
 *   3. Generates a fresh IV of the content algorithm's required length.
 *   4. Encrypts with AAD = `ASCII(Encoded Protected Header)`, or, when an
 *      explicit JWE AAD is supplied (JSON only), `ASCII(Encoded Protected
 *      Header || '.' || BASE64URL(JWE AAD))` (RFC 7516 §5.1 step 14).
 *   5. Hands the pieces to the chosen serializer.
 *
 * For the JSON serializations the caller may additionally supply a shared
 * `unprotected` header and a per-recipient `header`; their member names must be
 * disjoint from each other and from the protected header (enforced by
 * {@see JsonSerializer}). Those headers are *not* authenticated, so anything an
 * attacker must not be able to swap (notably the scheme's own `epk`/`iv`/`tag`)
 * stays in the protected header above.
 *
 * The recipient key is passed directly (as {@see \Medzuch\Jwt\Jws\Signer}
 * takes the signing key); the decrypt side resolves its key through a
 * {@see \Medzuch\Jwt\Key\KeyResolver}.
 */
final class Encrypter
{
    /**
     * Compact serialization (RFC 7516 §7.1).
     *
     * @param array<string, mixed> $protectedHeader caller-supplied header
     *                                              parameters (`typ`, `cty`,
     *                                              `kid`, …); `alg`/`enc` may be
     *                                              omitted (filled in) or
     *                                              provided (must match).
     *
     * @throws InvalidHeaderException if a caller-supplied `alg`/`enc` disagrees with the chosen algorithms
     */
    public function encrypt(
        KeyManagementAlgorithm $keyManagement,
        ContentEncryptionAlgorithm $contentEncryption,
        array $protectedHeader,
        string $plaintext,
        Key $recipientKey,
    ): CompactJwe {
        [$header, $encryptedKey, $iv, $ciphertext, $tag] = $this->establish($keyManagement, $contentEncryption, $protectedHeader, $plaintext, $recipientKey, null);

        return CompactSerializer::serialize($header, $encryptedKey, $iv, $ciphertext, $tag);
    }

    /**
     * Flattened JSON serialization (RFC 7516 §7.2.2).
     *
     * @param array<string, mixed> $protectedHeader   `alg`/`enc` plus any header to authenticate
     * @param array<string, mixed> $sharedUnprotected `unprotected` shared header (not authenticated)
     * @param array<string, mixed> $recipientHeader   the recipient's `header` (not authenticated)
     * @param ?string              $aad               raw Additional Authenticated Data, or null
     *
     * @throws InvalidHeaderException if `alg`/`enc` disagree, or the header sources share a member name
     */
    public function encryptFlattened(
        KeyManagementAlgorithm $keyManagement,
        ContentEncryptionAlgorithm $contentEncryption,
        array $protectedHeader,
        string $plaintext,
        Key $recipientKey,
        array $sharedUnprotected = [],
        array $recipientHeader = [],
        ?string $aad = null,
    ): FlattenedJwe {
        [$header, $encryptedKey, $iv, $ciphertext, $tag] = $this->establish($keyManagement, $contentEncryption, $protectedHeader, $plaintext, $recipientKey, $aad);

        return JsonSerializer::serializeFlattened($header, $sharedUnprotected, $recipientHeader, $encryptedKey, $iv, $ciphertext, $tag, $aad);
    }

    /**
     * General JSON serialization (RFC 7516 §7.2.1), single recipient.
     *
     * @param array<string, mixed> $protectedHeader   `alg`/`enc` plus any header to authenticate
     * @param array<string, mixed> $sharedUnprotected `unprotected` shared header (not authenticated)
     * @param array<string, mixed> $recipientHeader   the recipient's `header` (not authenticated)
     * @param ?string              $aad               raw Additional Authenticated Data, or null
     *
     * @throws InvalidHeaderException if `alg`/`enc` disagree, or the header sources share a member name
     */
    public function encryptGeneral(
        KeyManagementAlgorithm $keyManagement,
        ContentEncryptionAlgorithm $contentEncryption,
        array $protectedHeader,
        string $plaintext,
        Key $recipientKey,
        array $sharedUnprotected = [],
        array $recipientHeader = [],
        ?string $aad = null,
    ): GeneralJwe {
        [$header, $encryptedKey, $iv, $ciphertext, $tag] = $this->establish($keyManagement, $contentEncryption, $protectedHeader, $plaintext, $recipientKey, $aad);

        return JsonSerializer::serializeGeneral($header, $sharedUnprotected, $recipientHeader, $encryptedKey, $iv, $ciphertext, $tag, $aad);
    }

    /**
     * The shared establish-CEK-then-encrypt-content core behind all three
     * serializations. Returns the finalised protected header (with `alg`/`enc`
     * and any scheme-contributed parameters) and the four content pieces.
     *
     * @param array<string, mixed> $protectedHeader
     *
     * @return array{array<string, mixed>, string, string, string, string} [protectedHeader, encryptedKey, iv, ciphertext, tag]
     *
     * @throws InvalidHeaderException
     */
    private function establish(
        KeyManagementAlgorithm $keyManagement,
        ContentEncryptionAlgorithm $contentEncryption,
        array $protectedHeader,
        string $plaintext,
        Key $recipientKey,
        ?string $aad,
    ): array {
        $protectedHeader = self::withAlgEnc($protectedHeader, $keyManagement->name(), $contentEncryption->name());

        // ECDH-ES derives the key with empty PartyUInfo/PartyVInfo on the
        // encrypt side (this version). A caller-supplied `apu`/`apv` would ride
        // on the wire and feed the recipient's Concat KDF, yielding a different
        // CEK and an undecryptable token — so reject it rather than emit one.
        if ($keyManagement->family() === AlgorithmFamily::EcdhEs) {
            foreach (['apu', 'apv'] as $agreementParam) {
                if (array_key_exists($agreementParam, $protectedHeader)) {
                    throw new InvalidHeaderException(sprintf('Caller-supplied "%s" is not supported for ECDH-ES encryption in this version; omit it', $agreementParam));
                }
            }
        }

        $cek = $keyManagement->encryptKey($recipientKey, $contentEncryption);
        // Per-recipient parameters the scheme contributes (e.g. `epk` for
        // ECDH-ES, `iv`/`tag` for AES-GCM-KW) become part of the protected
        // header — and therefore part of the AAD computed from it. A scheme
        // must not use this channel to overwrite `alg`/`enc` and slip past the
        // agreement check above; reject it rather than let the merge clobber.
        foreach (['alg', 'enc'] as $reserved) {
            if (array_key_exists($reserved, $cek->headerParameters)) {
                throw new InvalidHeaderException(sprintf('Key-management algorithm "%s" must not contribute the reserved header parameter "%s"', $keyManagement->name(), $reserved));
            }
        }
        $protectedHeader = array_merge($protectedHeader, $cek->headerParameters);

        $encodedHeader = Base64Url::encode(Json::encode($protectedHeader));
        $iv = Random::bytes($contentEncryption->ivByteLength());
        [$ciphertext, $tag] = $contentEncryption->encrypt($plaintext, $cek->cek, $iv, self::additionalAuthenticatedData($encodedHeader, $aad));

        return [$protectedHeader, $cek->encryptedKey, $iv, $ciphertext, $tag];
    }

    /**
     * The AAD the content algorithm authenticates (RFC 7516 §5.1 step 14):
     * the encoded protected header, with `'.' || BASE64URL(JWE AAD)` appended
     * when an explicit JWE AAD is present. Mirrors
     * {@see ParsedJwe::additionalAuthenticatedData()} on the decrypt side.
     */
    private static function additionalAuthenticatedData(string $encodedProtectedHeader, ?string $aad): string
    {
        return $aad === null
            ? $encodedProtectedHeader
            : $encodedProtectedHeader . '.' . Base64Url::encode($aad);
    }

    /**
     * @param array<string, mixed> $header
     *
     * @return array<string, mixed>
     *
     * @throws InvalidHeaderException
     */
    private static function withAlgEnc(array $header, string $alg, string $enc): array
    {
        foreach (['alg' => $alg, 'enc' => $enc] as $param => $value) {
            if (array_key_exists($param, $header) && $header[$param] !== $value) {
                throw new InvalidHeaderException(sprintf('Header "%s" %s does not match the chosen algorithm "%s"', $param, self::describe($header[$param]), $value));
            }
            $header[$param] = $value;
        }

        return $header;
    }

    private static function describe(mixed $value): string
    {
        return match (true) {
            $value === null => 'null',
            is_string($value) => '"' . $value . '"',
            default => '(' . get_debug_type($value) . ')',
        };
    }
}
