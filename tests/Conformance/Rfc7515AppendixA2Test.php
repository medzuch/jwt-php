<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7515 Appendix A.2 — RSASSA-PKCS1-v1_5 SHA-256 worked example.
 *
 * RSA PKCS1-v1.5 signing is deterministic for a fixed (key, message),
 * so we assert byte-for-byte equality with the signature published in
 * §A.2.1 and with the full compact form in §A.2.2.
 */
#[CoversNothing]
final class Rfc7515AppendixA2Test extends TestCase
{
    /**
     * Compact form from RFC 7515 §A.2.2. Wrapped here for readability;
     * concatenated at use.
     */
    private const COMPACT
        = 'eyJhbGciOiJSUzI1NiJ9'
        . '.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        . '.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7'
        . 'AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4'
        . 'BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K'
        . '0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv'
        . 'hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB'
        . 'p0igcN_IoypGlUPQGe77Rw';

    /** @return array<string, string> */
    private static function jwk(): array
    {
        // The JWK from RFC 7515 §A.2.1. `alg: RS256` is injected because
        // this library requires the alg binding on every key (RFC 7517 §4.4);
        // the RFC's example JWK does not include it.
        return [
            'kty' => 'RSA',
            'alg' => 'RS256',
            'n' => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e' => 'AQAB',
            'd' => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p' => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q' => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp' => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1NaNFRAylohJktrAlOhrwR_qFM2yyJ1FWjPI28Pw5UfWWoKldDcZWg1ckCMC5XPiVrV9TpgtmgIeoXOLM',
            'dq' => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi' => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ];
    }

    public function testSignerReproducesTheVectorByteForByte(): void
    {
        // The signing input is `header.payload`; the signature in §A.2.1
        // is over those exact bytes. We hand the bytes to Signer via the
        // documented public API (header+payload), which round-trips through
        // base64url and concatenation identically to the RFC walkthrough.
        $headerJson = '{"alg":"RS256"}';
        $payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

        $privateKey = RsaPrivateKey::fromJwk(self::jwk());

        $jws = (new Signer())->sign(new Rs256(), ['alg' => 'RS256'], $payload, $privateKey);

        self::assertSame(self::COMPACT, $jws->value);

        $parsed = CompactSerializer::deserialize($jws->value);

        self::assertSame(
            Base64Url::decode('cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw'),
            $parsed->signature,
        );
        self::assertSame($payload, $parsed->payload);
        self::assertSame('RS256', $parsed->header['alg']);
        // The vector header is exactly `{"alg":"RS256"}` — no whitespace,
        // no `typ`. Json::decode is order-preserving, so this is a
        // round-trip check on the header bytes.
        self::assertSame($headerJson, json_encode($parsed->header));
    }

    public function testVerifierAcceptsTheRfcVector(): void
    {
        $parsed = CompactSerializer::deserialize(self::COMPACT);

        $jwk = self::jwk();
        $publicJwk = [
            'kty' => $jwk['kty'],
            'alg' => $jwk['alg'],
            'n' => $jwk['n'],
            'e' => $jwk['e'],
        ];

        $resolver = new StaticJwkSetResolver(JwkSet::of(RsaPublicKey::fromJwk($publicJwk)));

        $result = (new Verifier())->verify($parsed, [new Rs256()], $resolver);

        self::assertSame($parsed, $result);
    }
}
