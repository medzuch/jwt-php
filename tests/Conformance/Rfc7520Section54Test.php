<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Encryption\A128Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEsA128Kw;
use Medzuch\Jwt\Jwe\CompactSerializer;
use Medzuch\Jwt\Jwe\Decrypter;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7520 §5.4 — "Key Agreement with Key Wrapping Using ECDH-ES and
 * AES-KeyWrap with AES-GCM" (`ECDH-ES+A128KW` + `A128GCM`, on curve P-384).
 *
 * The cookbook publishes a complete compact JWE; decrypting it exercises the
 * key-agreement-with-wrapping path against an externally produced token —
 * the ECDH agreement (with the token's `epk`), the Concat KDF deriving the
 * AES-KW KEK, the AES key unwrap recovering the CEK, and the AES-GCM content
 * decryption — complementing the direct-mode RFC 7518 Appendix C vector.
 */
#[CoversNothing]
final class Rfc7520Section54Test extends TestCase
{
    /** §5.4 recipient EC key (Figure 108), bound to the example's alg. */
    private const RECIPIENT_JWK = [
        'kty' => 'EC',
        'kid' => 'peregrin.took@tuckborough.example',
        'use' => 'enc',
        'crv' => 'P-384',
        'x' => 'YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2',
        'y' => 'A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP',
        'd' => 'iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j',
        'alg' => 'ECDH-ES+A128KW',
    ];

    /** §5.4 complete JWE Compact Serialization (Figure 117). */
    private const COMPACT
        = 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdHVja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NHhBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMyZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0'
        . '.0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2'
        . '.mH-G2zVqgztUtnW_'
        . '.tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ'
        . '.WuGzxmcreYjpHGJoa17EBg';

    public function testDecryptsThePublishedTokenToTheCookbookPlaintext(): void
    {
        $key = EcPrivateKey::fromJwk(self::RECIPIENT_JWK);
        $resolver = new StaticJwkSetResolver(JwkSet::of($key));

        $parsed = CompactSerializer::deserialize(self::COMPACT);

        $plaintext = (new Decrypter())->decrypt($parsed, [new EcdhEsA128Kw()], [new A128Gcm()], $resolver);

        // Figure 72 — the abridged Fellowship of the Ring quote (U+2013 dashes).
        self::assertSame(
            "You can trust us to stick with you through thick and thin\u{2013}to the "
            . "bitter end. And you can trust us to keep any secret of yours\u{2013}closer "
            . 'than you keep it yourself. But you cannot trust us to let you face trouble '
            . 'alone, and go off without a word. We are your friends, Frodo.',
            $plaintext,
        );
    }
}
