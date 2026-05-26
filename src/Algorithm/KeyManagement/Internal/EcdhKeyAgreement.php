<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement\Internal;

use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\EcKey;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Primitives\Base64Url;
use OpenSSLAsymmetricKey;
use Throwable;

/**
 * The ECDH-ES key-agreement core shared by the direct and key-wrapping
 * variants (RFC 7518 §4.6): generate/parse the ephemeral key, run the raw
 * ECDH (`openssl_pkey_derive`), and feed the shared secret through the
 * {@see ConcatKdf}.
 *
 * Security-critical input validation lives here:
 *   - the recipient key must be an {@see EcKey} bound to the ECDH-ES `alg`;
 *   - the `epk` is loaded through {@see EcPublicKey::fromJwk}, whose OpenSSL
 *     `oct2point` round-trip rejects points that are not on the curve, and it
 *     must sit on the *same* curve as the recipient key. Together these defeat
 *     the invalid-curve attack (Antonio Sanso, 2017): an off-curve or
 *     wrong-curve `epk` is refused before any scalar multiplication with the
 *     static private key, so no information about the private scalar leaks.
 *
 * @internal consumed by the ECDH-ES key-management algorithms only
 */
final class EcdhKeyAgreement
{
    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * Sender side: agree a key with the recipient's static public key using a
     * fresh ephemeral key pair, returning the derived key material and the
     * `epk` protected-header parameter the recipient needs.
     *
     * @param positive-int $keyBytes
     *
     * @return array{0: non-empty-string, 1: array{epk: array<string, mixed>}}
     *
     * @throws KeyMismatchException
     * @throws DecryptionException
     */
    public static function deriveSenderKey(Key $recipientKey, string $algName, string $algorithmId, int $keyBytes): array
    {
        $recipient = self::recipientPublicKey($recipientKey, $algName);
        $curve = $recipient->curve();

        $ephemeral = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $curve->opensslName,
        ]);
        // @infection-ignore-all — backend fault on a supported curve; unreachable.
        if (!$ephemeral instanceof OpenSSLAsymmetricKey) {
            // @codeCoverageIgnoreStart
            throw new DecryptionException(sprintf('Failed to generate an ephemeral %s key', $curve->jwkName));
            // @codeCoverageIgnoreEnd
        }

        $z = openssl_pkey_derive($recipient->openSslKey(), $ephemeral);
        // @infection-ignore-all — backend fault with self-generated inputs; unreachable.
        if (!is_string($z) || $z === '') {
            // @codeCoverageIgnoreStart
            throw new DecryptionException('ECDH key agreement failed');
            // @codeCoverageIgnoreEnd
        }

        $derived = ConcatKdf::derive($z, $keyBytes, $algorithmId);

        return [$derived, ['epk' => self::ephemeralPublicJwk($ephemeral, $algName)]];
    }

    /**
     * Recipient side: recover the same derived key material from the token's
     * `epk` and the recipient's static private key.
     *
     * @param array<string, mixed> $header
     * @param positive-int         $keyBytes
     *
     * @return non-empty-string
     *
     * @throws KeyMismatchException
     * @throws DecryptionException
     */
    public static function deriveRecipientKey(Key $recipientKey, array $header, string $algName, string $algorithmId, int $keyBytes): string
    {
        $recipient = self::recipientPrivateKey($recipientKey, $algName);
        $epk = self::parseEpk($header, $recipient, $algName);

        $z = openssl_pkey_derive($epk->openSslKey(), $recipient->openSslKey());
        // @infection-ignore-all — unreachable once the epk is validated on-curve
        // and same-curve; a backend fault here cannot be provoked from tests.
        if (!is_string($z) || $z === '') {
            // @codeCoverageIgnoreStart
            throw new DecryptionException('ECDH key agreement failed');
            // @codeCoverageIgnoreEnd
        }

        [$apu, $apv] = self::partyInfo($header);

        return ConcatKdf::derive($z, $keyBytes, $algorithmId, $apu, $apv);
    }

    /**
     * @throws KeyMismatchException
     */
    private static function recipientPublicKey(Key $key, string $algName): EcPublicKey
    {
        // Encrypting needs only the recipient's public point; accept a private
        // key too (e.g. encrypting to one's own key) by taking its public part.
        if ($key instanceof EcPrivateKey) {
            $key = $key->toPublicKey();
        }
        if (!$key instanceof EcPublicKey) {
            throw new KeyMismatchException(sprintf('%s requires an EC key; got %s (RFC 8725 §3.1)', $algName, $key::class));
        }
        $key->assertAlgorithm($algName);
        if (!$key->allowsOperation('deriveKey')) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "deriveKey" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)'));
        }

        return $key;
    }

    /**
     * @throws KeyMismatchException
     */
    private static function recipientPrivateKey(Key $key, string $algName): EcPrivateKey
    {
        if (!$key instanceof EcPrivateKey) {
            throw new KeyMismatchException(sprintf('%s decryption requires an EC private key; got %s (RFC 8725 §3.1)', $algName, $key::class));
        }
        $key->assertAlgorithm($algName);
        if (!$key->allowsOperation('deriveKey')) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "deriveKey" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)'));
        }

        return $key;
    }

    /**
     * Load and validate the ephemeral public key from the `epk` header.
     *
     * @param array<string, mixed> $header
     *
     * @throws DecryptionException
     */
    private static function parseEpk(array $header, EcKey $recipient, string $algName): EcPublicKey
    {
        $epk = $header['epk'] ?? null;
        if (!is_array($epk)) {
            throw new DecryptionException('ECDH-ES JWE is missing the "epk" header parameter');
        }

        /** @var array<string, mixed> $epk */
        // Bind the ephemeral key to this alg so EcPublicKey::fromJwk accepts it
        // (the wire `epk` carries no `alg`); a private "d" is never allowed.
        $epk['alg'] = $algName;

        try {
            $epkKey = EcPublicKey::fromJwk($epk);
        } catch (InvalidKeyException $e) {
            // An off-curve point, an unsupported curve, or a malformed JWK all
            // collapse here — never leaking which (invalid-curve defence).
            throw new DecryptionException('ECDH-ES "epk" is not a valid public key on a supported curve', 0, $e);
        }

        if ($epkKey->curve()->jwkName !== $recipient->curve()->jwkName) {
            throw new DecryptionException(sprintf('ECDH-ES "epk" curve "%s" does not match the recipient key curve "%s"', $epkKey->curve()->jwkName, $recipient->curve()->jwkName));
        }

        return $epkKey;
    }

    /**
     * Decode the optional `apu` / `apv` agreement-info parameters.
     *
     * @param array<string, mixed> $header
     *
     * @return array{0: string, 1: string}
     *
     * @throws DecryptionException
     */
    private static function partyInfo(array $header): array
    {
        return [self::decodeOptionalB64($header, 'apu'), self::decodeOptionalB64($header, 'apv')];
    }

    /**
     * @param array<string, mixed> $header
     *
     * @throws DecryptionException
     */
    private static function decodeOptionalB64(array $header, string $param): string
    {
        $value = $header[$param] ?? null;
        if ($value === null) {
            return '';
        }
        if (!is_string($value)) {
            throw new DecryptionException(sprintf('ECDH-ES "%s" header parameter must be a string', $param));
        }

        try {
            return Base64Url::decode($value);
        } catch (Throwable $e) {
            throw new DecryptionException(sprintf('ECDH-ES "%s" header parameter is not valid base64url', $param), 0, $e);
        }
    }

    /**
     * Build the `epk` JWK ({kty, crv, x, y}) for a freshly generated ephemeral
     * key — no `alg`/`kid`, matching the RFC 7518 examples. Round-trips the
     * ephemeral public PEM through {@see EcPublicKey} so coordinate padding and
     * encoding reuse the already-tested key code rather than re-deriving it.
     *
     * @return array<string, mixed>
     */
    private static function ephemeralPublicJwk(OpenSSLAsymmetricKey $ephemeral, string $algName): array
    {
        $details = openssl_pkey_get_details($ephemeral);
        // @infection-ignore-all — backend fault on a self-generated key; unreachable.
        if ($details === false) {
            // @codeCoverageIgnoreStart
            throw new DecryptionException('OpenSSL did not return ephemeral key details');
            // @codeCoverageIgnoreEnd
        }
        $pem = $details['key'] ?? null;
        // @infection-ignore-all — backend fault on a self-generated key; unreachable.
        if (!is_string($pem)) {
            // @codeCoverageIgnoreStart
            throw new DecryptionException('OpenSSL did not return the ephemeral public key');
            // @codeCoverageIgnoreEnd
        }

        try {
            $jwk = EcPublicKey::fromPem($pem, $algName)->toJwk();
        } catch (InvalidKeyException $e) {
            // @codeCoverageIgnoreStart
            throw new DecryptionException('Failed to encode the ephemeral public key', 0, $e);
            // @codeCoverageIgnoreEnd
        }

        return ['kty' => 'EC', 'crv' => $jwk['crv'], 'x' => $jwk['x'], 'y' => $jwk['y']];
    }
}
