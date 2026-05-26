<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwe;

use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\Random;

/**
 * Produces a compact JWE from a plaintext, a protected header, a key-
 * management algorithm, a content-encryption algorithm, and the recipient
 * key (RFC 7516 §5.1).
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
 *   3. Generates a fresh IV of the content algorithm's required length.
 *   4. Encrypts with AAD = `ASCII(BASE64URL(Protected Header))` (RFC 7516
 *      §5.1 step 14) — the same header bytes the serializer emits.
 *   5. Assembles the five compact segments.
 *
 * The recipient key is passed directly (as {@see \Medzuch\Jwt\Jws\Signer}
 * takes the signing key); the decrypt side resolves its key through a
 * {@see \Medzuch\Jwt\Key\KeyResolver}.
 */
final class Encrypter
{
    /**
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
        $protectedHeader = self::withAlgEnc($protectedHeader, $keyManagement->name(), $contentEncryption->name());

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
        [$ciphertext, $tag] = $contentEncryption->encrypt($plaintext, $cek->cek, $iv, $encodedHeader);

        return CompactSerializer::serialize($protectedHeader, $cek->encryptedKey, $iv, $ciphertext, $tag);
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
