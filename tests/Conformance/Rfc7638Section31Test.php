<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Key\Thumbprint;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7638 §3.1 — JWK thumbprint worked example.
 *
 * The example key carries `alg` and `kid` beside its required members, so
 * the vector doubles as the guard against hashing `toJwk()` unfiltered:
 * those two members must not reach the digest.
 */
#[CoversNothing]
final class Rfc7638Section31Test extends TestCase
{
    private const N = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';

    /** RFC 7638 §3.1 — the JSON the thumbprint is computed over. */
    private const HASH_INPUT = '{"e":"AQAB","kty":"RSA","n":"' . self::N . '"}';

    private const THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    public function testPublishedHashInputDigestsToPublishedThumbprint(): void
    {
        self::assertSame(self::THUMBPRINT, Base64Url::encode(hash('sha256', self::HASH_INPUT, true)));
    }

    public function testThumbprintOfExampleKeyMatchesPublishedValue(): void
    {
        $key = RsaPublicKey::fromJwk([
            'kty' => 'RSA',
            'n' => self::N,
            'e' => 'AQAB',
            'alg' => 'RS256',
            'kid' => '2011-04-29',
        ]);

        self::assertSame(self::THUMBPRINT, Thumbprint::of($key));
        self::assertTrue(Thumbprint::matches($key, self::THUMBPRINT));
    }
}
