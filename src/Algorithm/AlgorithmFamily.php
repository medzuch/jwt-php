<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm;

/**
 * Coarse grouping of JOSE algorithms by underlying primitive.
 *
 * Used by upper layers (key resolvers, profiles, the JWE Encrypter /
 * Decrypter) that need to reason about families without enumerating every
 * `alg` / `enc` name.
 *
 * The first block is the JWS signing families (RFC 7518 §3). The second is
 * the JWE families (RFC 7518 §4–§5): the key-management families that derive
 * or transport the Content Encryption Key, and the content-encryption (AEAD)
 * families that protect the plaintext. RSA key-management (RSA-OAEP, RSA1_5)
 * is intentionally absent — deferred out of v0.3, see docs/12-decisions.md
 * (D-003).
 */
enum AlgorithmFamily
{
    // JWS signing (RFC 7518 §3).
    case Hmac;
    case Rsa;
    case Ecdsa;
    case EdDsa;
    case None;

    // JWE key management (RFC 7518 §4).
    case Direct;     // `dir`: the shared symmetric key is the CEK.
    case AesKw;      // A128KW / A192KW / A256KW (RFC 3394 key wrap).
    case AesGcmKw;   // A128GCMKW / A192GCMKW / A256GCMKW.
    case EcdhEs;     // ECDH-ES and ECDH-ES+A*KW.

    // JWE content encryption (RFC 7518 §5).
    case AesCbcHmac; // A128CBC-HS256 / A192CBC-HS384 / A256CBC-HS512.
    case AesGcm;     // A128GCM / A192GCM / A256GCM.
}
