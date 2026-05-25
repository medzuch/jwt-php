<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\Encryption\A128CbcHs256;
use Medzuch\Jwt\Algorithm\Encryption\A192CbcHs384;
use Medzuch\Jwt\Algorithm\Encryption\A256CbcHs512;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7518 Appendix B — AES_CBC_HMAC_SHA2 test cases.
 *
 * The composed CBC+HMAC AEAD is deterministic given a fixed IV, so unlike the
 * non-deterministic signature cookbooks we can reproduce the published
 * ciphertext and authentication tag byte-for-byte. Each case feeds the RFC's
 * key, plaintext, IV, and AAD straight into the content-encryption algorithm
 * and asserts the ciphertext (E) and tag (T) match §B.1–§B.3, then confirms
 * decryption round-trips.
 *
 * The plaintext P and AAD A are identical across all three cases (a Kerckhoffs
 * quote and its attribution); only the key length and hash differ.
 */
#[CoversNothing]
final class Rfc7518AppendixBTest extends TestCase
{
    /** §B common plaintext P. */
    private const PLAINTEXT
        = 'A cipher system must not be required to be secret, and it must be '
        . 'able to fall into the hands of the enemy without inconvenience';

    /** §B common Additional Authenticated Data A. */
    private const AAD = 'The second principle of Auguste Kerckhoffs';

    /** §B common IV. */
    private const IV = '1af38c2dc2b96ffdd86694092341bc04';

    /** @return iterable<string, array{ContentEncryptionAlgorithm, string, string, string}> */
    public static function vectorProvider(): iterable
    {
        // B.1 — AES_128_CBC_HMAC_SHA_256
        yield 'A128CBC-HS256' => [
            new A128CbcHs256(),
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
            'c80edfa32ddf39d5ef00c0b468834279 a2e46a1b8049f792f76bfe54b903a9c9
             a94ac9b47ad2655c5f10f9aef71427e2 fc6f9b3f399a221489f16362c7032336
             09d45ac69864e3321cf82935ac4096c8 6e133314c54019e8ca7980dfa4b9cf1b
             384c486f3a54c51078158ee5d79de59f bd34d848b3d69550a676463444 27ade5
             4b8851ffb598f7f80074b9473c82e2db',
            '652c3fa36b0a7c5b3219fab3a30bc1c4',
        ];

        // B.2 — AES_192_CBC_HMAC_SHA_384
        yield 'A192CBC-HS384' => [
            new A192CbcHs384(),
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
            . '202122232425262728292a2b2c2d2e2f',
            'ea65da6b59e61edb419be62d19712ae5 d303eeb50052d0dfd6697f77224c8edb
             000d279bdc14c1072654bd30944230c6 57bed4ca0c9f4a8466f22b226d174621
             4bf8cfc2400add9f5126e479663fc90b 3bed787a2f0ffcbf3904be2a641d5c21
             05bfe591bae23b1d7449e532eef60a9a c8bb6c6b01d35d49787bcd57ef484927
             f280adc91ac0c4e79c7b11efc60054e3',
            '8490ac0e58949bfe51875d733f93ac20 7516803 9ccc733d7',
        ];

        // B.3 — AES_256_CBC_HMAC_SHA_512
        yield 'A256CBC-HS512' => [
            new A256CbcHs512(),
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
            . '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
            '4affaaadb78c31c5da4b1b590d10ffbd 3dd8d5d30242352691 2da037ecbcc7bd
             822c301dd67c373bccb584ad3e9279c2 e6d12a1374b77f077553df8294104 46b
             36ebd97066296ae6427ea75c2e0846a1 1a09ccf5370dc80bfecbad28c73f09b3
             a3b75e662a2594410ae496b2e2e6609e 31e6e02cc837f053d21f37ff4f51950b
             be2638d09dd7a49309308 06d0703b1f6',
            '4dd3b4c088a7f45c216839645b2012bf 2e6269a8c56a816dbc1b267761955bc5',
        ];
    }

    #[DataProvider('vectorProvider')]
    public function testReproducesPublishedCiphertextAndTag(
        ContentEncryptionAlgorithm $alg,
        string $keyHex,
        string $ciphertextHex,
        string $tagHex,
    ): void {
        [$ciphertext, $tag] = $alg->encrypt(self::PLAINTEXT, self::hex($keyHex), self::hex(self::IV), self::AAD);

        self::assertSame(self::hex($ciphertextHex), $ciphertext, 'ciphertext (E) must match the RFC vector');
        self::assertSame(self::hex($tagHex), $tag, 'authentication tag (T) must match the RFC vector');
    }

    #[DataProvider('vectorProvider')]
    public function testDecryptsPublishedCiphertext(
        ContentEncryptionAlgorithm $alg,
        string $keyHex,
        string $ciphertextHex,
        string $tagHex,
    ): void {
        $plaintext = $alg->decrypt(self::hex($ciphertextHex), self::hex($keyHex), self::hex(self::IV), self::hex($tagHex), self::AAD);

        self::assertSame(self::PLAINTEXT, $plaintext);
    }

    /** Decode hex, tolerating the whitespace used to lay the vectors out. */
    private static function hex(string $hex): string
    {
        return (string) hex2bin((string) preg_replace('/[^0-9a-fA-F]/', '', $hex));
    }
}
