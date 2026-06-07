<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Benchmarks;

/**
 * Fixed key material shared by every library under test, generated once per
 * process so all three libraries sign and verify with byte-identical keys.
 *
 * RSA-2048 and EC P-256 are the sizes overwhelmingly used in production
 * (RS256/ES256). The HMAC secret is 256-bit, the minimum sane size for HS256.
 */
final class Keys
{
    public readonly string $hmacSecret;
    public readonly string $rsaPrivatePem;
    public readonly string $rsaPublicPem;
    public readonly string $ecPrivatePem;
    public readonly string $ecPublicPem;

    public function __construct()
    {
        $this->hmacSecret = random_bytes(32);

        [$this->rsaPrivatePem, $this->rsaPublicPem] = self::generate([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        [$this->ecPrivatePem, $this->ecPublicPem] = self::generate([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array{0: string, 1: string} [privatePem, publicPem]
     */
    private static function generate(array $config): array
    {
        $resource = openssl_pkey_new($config);
        if ($resource === false) {
            throw new \RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
        }

        openssl_pkey_export($resource, $privatePem);
        $publicPem = openssl_pkey_get_details($resource)['key'];

        return [$privatePem, $publicPem];
    }
}
