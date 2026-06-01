<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jwe\CompactJwe;
use Medzuch\Jwt\Jwe\Encrypter;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Key\Key;

/**
 * Wraps an already-signed JWS as an encrypted JWE — the sign-then-encrypt
 * leg of an RFC 7519 §5.2 nested JWT.
 *
 * Sign-then-encrypt is the order RFC 7519 §11.2 recommends and the order
 * the threat model commits to (T4): the producer cannot encrypt unsigned
 * plaintext through this entry point because the input type is
 * {@see CompactJws}. The reverse pattern (encrypt-then-sign) is not
 * supported.
 *
 * The outer JWE protected header MUST declare `cty: "JWT"` so the recipient
 * knows the plaintext is itself a JWT (RFC 7519 §5.2); the helper supplies
 * it if the caller has not. Setting an explicit outer `typ` is encouraged
 * (RFC 8725 §3.11 closing paragraph) but optional. Claims a caller wishes
 * to replicate as outer header parameters per RFC 7519 §5.3 are added by
 * the caller; the {@see NestedJwtParser} enforces value equality on parse.
 *
 * For more involved outer-header needs — shared unprotected headers, an
 * explicit `aad`, the general JSON serialization — call
 * {@see Encrypter::encryptFlattened()} / `encryptGeneral()` directly with
 * the same {@see CompactJws}-as-plaintext recipe.
 */
final class NestedJwtBuilder
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * Wrap a signed JWS in a JWE, compact serialization.
     *
     * @param array<string, mixed> $outerProtectedHeader caller-supplied protected
     *                                                   header — `cty` is set to
     *                                                   `"JWT"` if absent and
     *                                                   refused if present with a
     *                                                   different value; `alg`
     *                                                   and `enc` are filled in
     *                                                   by {@see Encrypter}
     *
     * @throws InvalidHeaderException if `cty` is present and not exactly `"JWT"`
     */
    public static function wrap(
        CompactJws $innerJws,
        KeyManagementAlgorithm $keyManagement,
        ContentEncryptionAlgorithm $contentEncryption,
        Key $recipientKey,
        array $outerProtectedHeader = [],
    ): CompactJwe {
        $outerProtectedHeader = self::withNestedContentType($outerProtectedHeader);

        return (new Encrypter())->encrypt(
            $keyManagement,
            $contentEncryption,
            $outerProtectedHeader,
            $innerJws->value,
            $recipientKey,
        );
    }

    /**
     * `cty: "JWT"` is the marker RFC 7519 §5.2 mandates so the recipient
     * knows the plaintext is a JWT. The wrap helper supplies it when absent
     * and refuses to silently overwrite a caller-provided non-`"JWT"` value —
     * a caller setting `cty` to anything else has either confused JWT with
     * a different content type or built the nested token by hand and should
     * use {@see Encrypter::encrypt()} directly.
     *
     * @param array<string, mixed> $header
     *
     * @return array<string, mixed>
     *
     * @throws InvalidHeaderException
     */
    private static function withNestedContentType(array $header): array
    {
        if (!array_key_exists('cty', $header)) {
            $header['cty'] = 'JWT';

            return $header;
        }
        if ($header['cty'] !== 'JWT') {
            throw new InvalidHeaderException(sprintf('Nested JWT outer header "cty" must be "JWT" (RFC 7519 §5.2); got %s', self::describe($header['cty'])));
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
