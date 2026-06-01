<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Encryption\A128CbcHs256;
use Medzuch\Jwt\Algorithm\KeyManagement\A128Kw;
use Medzuch\Jwt\Jwe\CompactSerializer;
use Medzuch\Jwt\Jwe\Decrypter;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7516 Appendix A.3 — the canonical "AES Key Wrap + AES_128_CBC_HMAC_SHA_256"
 * worked example, and the headline conformance exit vector for the JWE
 * key-wrapping work (Phase 3, roadmap §Phase 3 exit criteria).
 *
 * AES Key Wrap and AES-CBC-HMAC are both deterministic, so §A.3 publishes a
 * complete compact JWE that any conforming implementation must decrypt to the
 * plaintext "Live long and prosper.". This test drives the *real* end-to-end
 * decrypt path — {@see CompactSerializer} → {@see Decrypter} → {@see A128Kw}
 * unwrap → {@see A128CbcHs256} authenticated decrypt — over the published
 * token, exactly as a relying party would.
 *
 * The §A.3 protected header carries no `kid`; resolution therefore succeeds via
 * the resolver's `alg`-fallback, which lands on the right key precisely because
 * a key-wrapping KEK is bound to the key-management `alg` (here `A128KW`) — the
 * very case the fallback was designed for.
 */
#[CoversNothing]
final class Rfc7516AppendixA3Test extends TestCase
{
    /** §A.3.7 complete compact serialization. */
    private const COMPACT
        = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.'
        . '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.'
        . 'AxY8DCtDaGlsbGljb3RoZQ.'
        . 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.'
        . 'U0m_YmjN04DJvceFICbCVQ';

    /** §A.3.3 shared symmetric key {"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}. */
    private const KEK_K = 'GawgguFyGrWKav7AX4VKUg';

    public function testDecryptsThePublishedTokenToTheRfcPlaintext(): void
    {
        $kek = OctKey::fromBinary(Base64Url::decode(self::KEK_K), 'A128KW', kid: 'a3');
        $resolver = new StaticJwkSetResolver(JwkSet::of($kek));

        $parsed = CompactSerializer::deserialize(self::COMPACT);

        $plaintext = (new Decrypter())->decrypt($parsed, [new A128Kw()], [new A128CbcHs256()], $resolver);

        self::assertSame('Live long and prosper.', $plaintext);
    }
}
