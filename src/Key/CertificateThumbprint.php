<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Primitives\Base64Url;
use SodiumException;

/**
 * X.509 certificate SHA-256 thumbprint (RFC 8705 §3.1) — the base64url
 * SHA-256 of the certificate's DER encoding, carried by an mTLS-bound
 * access token as `cnf.x5t#S256`.
 *
 * The digest covers the bytes as given; nothing is parsed and re-encoded.
 * The only structural check is that the input is one DER SEQUENCE spanning
 * the whole string, which catches PEM or base64 passed as DER and truncated
 * or padded buffers — each of which would otherwise yield a thumbprint that
 * silently matches nothing. It is not certificate validation: chain,
 * expiry and revocation belong to the layer that terminated TLS.
 *
 * {@see ofPem()} takes what a TLS-terminating proxy forwards:
 *
 *   - exactly one `CERTIFICATE` block (RFC 7468 §5), optionally surrounded
 *     by whitespace;
 *   - a base64 body wrapped at any width, on one line, or with its line
 *     breaks folded into spaces;
 *   - the whole block percent-encoded (nginx `$ssl_client_escaped_cert`,
 *     Envoy's `x-forwarded-client-cert`). `%` cannot occur in PEM, so its
 *     presence identifies the encoding, and it is undone with
 *     `rawurldecode()` — never `urldecode()`, which turns every `+` of the
 *     base64 body into a space.
 *
 * A chain is refused rather than reduced to its first member: which
 * certificate authenticated the connection is the proxy's knowledge, not
 * something to guess from order. So is any other label, including OpenSSL's
 * `TRUSTED CERTIFICATE`, whose trailer is not part of the certificate.
 */
final class CertificateThumbprint
{
    private const PEM_PATTERN = '/\A[ \t\r\n]*-----BEGIN CERTIFICATE-----([A-Za-z0-9+\/= \t\r\n]+)-----END CERTIFICATE-----[ \t\r\n]*\z/';

    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * @throws InvalidKeyException if $der is not a single DER SEQUENCE
     */
    public static function ofDer(string $der): string
    {
        try {
            Asn1::assertSingleSequence($der);
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException('Certificate is not a single DER structure (for PEM input use ofPem()): ' . $e->getMessage(), previous: $e);
        }

        return Base64Url::encode(hash('sha256', $der, true));
    }

    /**
     * @throws InvalidKeyException if $pem is not exactly one well-formed CERTIFICATE block
     */
    public static function ofPem(string $pem): string
    {
        if (str_contains($pem, '%')) {
            $pem = rawurldecode($pem);
        }
        if (substr_count($pem, '-----BEGIN ') > 1) {
            throw new InvalidKeyException('PEM holds more than one block; pass the client certificate alone, not a chain');
        }
        if (preg_match(self::PEM_PATTERN, $pem, $match) !== 1) {
            throw new InvalidKeyException('Input is not a single PEM CERTIFICATE block (RFC 7468 §5)');
        }

        try {
            $der = sodium_base642bin($match[1], SODIUM_BASE64_VARIANT_ORIGINAL, " \t\r\n");
        } catch (SodiumException $e) {
            throw new InvalidKeyException('PEM CERTIFICATE body is not valid base64', previous: $e);
        }

        return self::ofDer($der);
    }
}
