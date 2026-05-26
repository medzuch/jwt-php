<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\KeyManagement\Internal\EcdhKeyAgreement;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7518 Appendix C — the worked ECDH-ES key-agreement example (producer
 * Alice → consumer Bob, "alg":"ECDH-ES", "enc":"A128GCM", with non-empty
 * "apu"/"apv").
 *
 * This drives the real recipient-side agreement: Bob's static private key plus
 * Alice's published ephemeral public key (`epk`) and agreement-info headers
 * must reproduce the published 128-bit derived key (which, for direct
 * ECDH-ES, is the CEK). It exercises the whole path — `epk` parsing and
 * on-curve validation, the raw ECDH, and the Concat KDF including the
 * non-empty PartyUInfo/PartyVInfo — against an externally produced vector.
 */
#[CoversNothing]
final class Rfc7518AppendixCTest extends TestCase
{
    public function testRecipientDerivesThePublishedKey(): void
    {
        $bob = EcPrivateKey::fromJwk([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            'alg' => 'ECDH-ES',
        ]);

        $header = [
            'alg' => 'ECDH-ES',
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U', // "Alice"
            'apv' => 'Qm9i',    // "Bob"
            'epk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
                'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            ],
        ];

        $derived = EcdhKeyAgreement::deriveRecipientKey($bob, $header, 'ECDH-ES', 'A128GCM', 16);

        // §C: the resulting derived key is base64url "VqqN6vgjbSBcIijNcacQGg".
        self::assertSame('VqqN6vgjbSBcIijNcacQGg', Base64Url::encode($derived));
    }
}
