<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Encryption\A128CbcHs256;
use Medzuch\Jwt\Algorithm\Encryption\A128Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A128Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\EcdhEsA128Kw;
use Medzuch\Jwt\Jwe\Decrypter;
use Medzuch\Jwt\Jwe\JsonSerializer;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * JSON-serialization conformance for the JWE decrypt path.
 *
 * The published RFC vectors are compact, so this test recomposes their exact
 * on-the-wire segments — the same `protected` header bytes, Encrypted Key, IV,
 * ciphertext, and tag — into the flattened and general JSON serializations of
 * RFC 7516 §7.2 and decrypts them. Because the `protected` member preserves the
 * very bytes that feed the AAD, a correct JSON parse must recover the identical
 * plaintext the compact form does:
 *
 *   - RFC 7516 §A.3 — `A128KW` + `A128CBC-HS256` (symmetric).
 *   - RFC 7520 §5.4 — `ECDH-ES+A128KW` + `A128GCM` (key agreement with wrapping).
 *
 * This is the JSON counterpart to {@see Rfc7516AppendixA3Test} and
 * {@see Rfc7520Section54Test}, and covers the in-scope cookbook encryption
 * vectors (symmetric + ECDH-ES) in JSON form for the Phase 3 exit criteria.
 */
#[CoversNothing]
final class Rfc7516JweJsonSerializationTest extends TestCase
{
    /** RFC 7516 §A.3.7 complete compact serialization. */
    private const A3_COMPACT
        = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.'
        . '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.'
        . 'AxY8DCtDaGlsbGljb3RoZQ.'
        . 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.'
        . 'U0m_YmjN04DJvceFICbCVQ';

    /** RFC 7516 §A.3.3 shared symmetric key {"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}. */
    private const A3_KEK_K = 'GawgguFyGrWKav7AX4VKUg';

    /** RFC 7520 §5.4 recipient EC key (Figure 108). */
    private const S54_RECIPIENT_JWK = [
        'kty' => 'EC',
        'kid' => 'peregrin.took@tuckborough.example',
        'use' => 'enc',
        'crv' => 'P-384',
        'x' => 'YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2',
        'y' => 'A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP',
        'd' => 'iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j',
        'alg' => 'ECDH-ES+A128KW',
    ];

    /** RFC 7520 §5.4 complete compact serialization (Figure 117). */
    private const S54_COMPACT
        = 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdHVja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NHhBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMyZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0'
        . '.0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2'
        . '.mH-G2zVqgztUtnW_'
        . '.tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ'
        . '.WuGzxmcreYjpHGJoa17EBg';

    public function testDecryptsAppendixA3FromFlattenedJson(): void
    {
        $resolver = new StaticJwkSetResolver(JwkSet::of(OctKey::fromBinary(Base64Url::decode(self::A3_KEK_K), 'A128KW', kid: 'a3')));

        $parsed = JsonSerializer::deserialize(self::flattened(self::A3_COMPACT));
        $plaintext = (new Decrypter())->decrypt($parsed, [new A128Kw()], [new A128CbcHs256()], $resolver);

        self::assertSame('Live long and prosper.', $plaintext);
    }

    public function testDecryptsAppendixA3FromGeneralJson(): void
    {
        $resolver = new StaticJwkSetResolver(JwkSet::of(OctKey::fromBinary(Base64Url::decode(self::A3_KEK_K), 'A128KW', kid: 'a3')));

        $parsed = JsonSerializer::deserialize(self::general(self::A3_COMPACT));
        $plaintext = (new Decrypter())->decrypt($parsed, [new A128Kw()], [new A128CbcHs256()], $resolver);

        self::assertSame('Live long and prosper.', $plaintext);
    }

    public function testDecryptsSection54FromFlattenedJson(): void
    {
        $resolver = new StaticJwkSetResolver(JwkSet::of(EcPrivateKey::fromJwk(self::S54_RECIPIENT_JWK)));

        $parsed = JsonSerializer::deserialize(self::flattened(self::S54_COMPACT));
        $plaintext = (new Decrypter())->decrypt($parsed, [new EcdhEsA128Kw()], [new A128Gcm()], $resolver);

        self::assertSame(self::SECTION_54_PLAINTEXT, $plaintext);
    }

    public function testDecryptsSection54FromGeneralJson(): void
    {
        $resolver = new StaticJwkSetResolver(JwkSet::of(EcPrivateKey::fromJwk(self::S54_RECIPIENT_JWK)));

        $parsed = JsonSerializer::deserialize(self::general(self::S54_COMPACT));
        $plaintext = (new Decrypter())->decrypt($parsed, [new EcdhEsA128Kw()], [new A128Gcm()], $resolver);

        self::assertSame(self::SECTION_54_PLAINTEXT, $plaintext);
    }

    /** Figure 72 — the abridged Fellowship of the Ring quote (U+2013 dashes). */
    private const SECTION_54_PLAINTEXT
        = "You can trust us to stick with you through thick and thin\u{2013}to the "
        . "bitter end. And you can trust us to keep any secret of yours\u{2013}closer "
        . 'than you keep it yourself. But you cannot trust us to let you face trouble '
        . 'alone, and go off without a word. We are your friends, Frodo.';

    /** Recompose the compact token's exact segments as a flattened JSON JWE. */
    private static function flattened(string $compact): string
    {
        [$protected, $encryptedKey, $iv, $ciphertext, $tag] = explode('.', $compact);

        return Json::encode([
            'protected' => $protected,
            'encrypted_key' => $encryptedKey,
            'iv' => $iv,
            'ciphertext' => $ciphertext,
            'tag' => $tag,
        ]);
    }

    /** Recompose the compact token's exact segments as a general JSON JWE. */
    private static function general(string $compact): string
    {
        [$protected, $encryptedKey, $iv, $ciphertext, $tag] = explode('.', $compact);

        return Json::encode([
            'protected' => $protected,
            'recipients' => [['encrypted_key' => $encryptedKey]],
            'iv' => $iv,
            'ciphertext' => $ciphertext,
            'tag' => $tag,
        ]);
    }
}
