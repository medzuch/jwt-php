<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\Signing;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\OkpPrivateKey;
use Medzuch\Jwt\Key\OkpPublicKey;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Key\PublicKey;
use SodiumException;

/**
 * Edwards-curve Digital Signature Algorithm using Ed25519 (RFC 8037 §3.1).
 *
 * Unlike the other JOSE signing algorithms there is exactly one `EdDSA`
 * algorithm name — the curve identifies the variant. This library currently
 * implements only Ed25519 (Ed448 is not exposed by PHP's libsodium).
 *
 * Ed25519 signing is deterministic by construction (RFC 8032 §5.1.6): the
 * per-signature nonce is derived from the message and a hash of the secret
 * key, not a random source. Two signatures over the same input are equal,
 * which we assert on in tests and which makes RFC 8037 §A.4 reproducible
 * byte-for-byte.
 */
final class EdDsa implements SigningAlgorithm
{
    public function name(): string
    {
        return 'EdDSA';
    }

    public function family(): AlgorithmFamily
    {
        return AlgorithmFamily::EdDsa;
    }

    public function sign(string $input, PrivateKey $key): string
    {
        if (!$key instanceof OkpPrivateKey) {
            throw new KeyMismatchException(sprintf('EdDSA requires OkpPrivateKey; got %s (RFC 8725 §3.1)', $key::class));
        }
        $key->assertAlgorithm($this->name());
        if (!$key->allowsOperation('sign')) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "sign" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)'));
        }

        $signature = sodium_crypto_sign_detached($input, $key->secretKeyBytes());

        /** @var non-empty-string $signature exactly SODIUM_CRYPTO_SIGN_BYTES (64) */
        return $signature;
    }

    public function verify(string $input, string $signature, PublicKey $key): bool
    {
        if (!$key instanceof OkpPublicKey) {
            throw new KeyMismatchException(sprintf('EdDSA requires OkpPublicKey; got %s (RFC 8725 §3.1)', $key::class));
        }
        $key->assertAlgorithm($this->name());
        if (!$key->allowsOperation('verify')) {
            throw new KeyMismatchException(sprintf('Key %s does not permit operation "verify" (RFC 7517 §4.3)', $key->kid() ?? '(no kid)'));
        }

        // An empty signature can never verify; sodium_crypto_sign_verify_detached
        // refuses non-empty-string at the type level, so guard here.
        if ($signature === '') {
            return false;
        }

        // libsodium throws SodiumException on a malformed signature (wrong
        // length, etc.) rather than returning false. Treat that as "not
        // verified" — same surface behaviour as a cryptographically invalid
        // signature, and stops attackers probing via malformed input.
        try {
            return sodium_crypto_sign_verify_detached($signature, $input, $key->publicKeyBytes());
        } catch (SodiumException) {
            return false;
        }
    }
}
