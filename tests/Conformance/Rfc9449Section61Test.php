<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Key\JwkParser;
use Medzuch\Jwt\Key\Thumbprint;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9449 §6.1 — the `cnf.jkt` of the example access token is the RFC 7638
 * thumbprint of the key in the example DPoP proof header (§4.1).
 *
 * Only the thumbprint half of DPoP: verifying the proof itself is out of
 * scope here. The proof's `jwk` carries no `alg`, so the key is built with the
 * proof header's `alg` — the path an authorization server takes when binding
 * a token to a proof it has just verified.
 */
#[CoversNothing]
final class Rfc9449Section61Test extends TestCase
{
    /** RFC 9449 §4.1 — decoded DPoP proof header. */
    private const PROOF_HEADER = [
        'typ' => 'dpop+jwt',
        'alg' => 'ES256',
        'jwk' => [
            'kty' => 'EC',
            'x' => 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs',
            'y' => '9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA',
            'crv' => 'P-256',
        ],
    ];

    /** RFC 9449 §6.1 — `cnf.jkt` of the example access token. */
    private const JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';

    public function testProofKeyThumbprintIsTheExampleJkt(): void
    {
        $key = JwkParser::parse([...self::PROOF_HEADER['jwk'], 'alg' => self::PROOF_HEADER['alg']]);

        self::assertSame(self::JKT, Thumbprint::of($key));
    }

    public function testExampleAccessTokenConfirmationMatchesTheProofKey(): void
    {
        $claims = new ClaimsSet([
            'sub' => 'someone@example.com',
            'iss' => 'https://server.example.com',
            'nbf' => 1_562_262_611,
            'exp' => 1_562_266_216,
            'cnf' => ['jkt' => self::JKT],
        ]);
        $key = JwkParser::parse([...self::PROOF_HEADER['jwk'], 'alg' => self::PROOF_HEADER['alg']]);

        $jkt = $claims->confirmation()?->jkt();

        self::assertNotNull($jkt);
        self::assertTrue(Thumbprint::matches($key, $jkt));
    }
}
