<?php

declare(strict_types=1);

/**
 * Cross-library JWT benchmark: medzuch/jwt-php vs firebase/php-jwt vs
 * web-token/jwt-framework vs lcobucci/jwt, across HS256 / RS256 / ES256, for
 * both issuing (sign) and verifying (parse + signature check) a compact JWS.
 *
 * Run:  docker compose exec php php benchmarks/run.php
 * Tune: BENCH_BUDGET=2.0 docker compose exec php php benchmarks/run.php
 *
 * Reusable per-consumer objects (algorithm managers, validators, key objects)
 * are constructed ONCE, outside the timed loop — the realistic hot path is
 * "build the consumer once, verify many tokens". Only the per-token issue /
 * verify call is timed. Read docs/14-performance.md for what the numbers mean;
 * the libraries do NOT all validate the same amount on verify (see that doc).
 */

use Firebase\JWT\JWT as FirebaseJwt;
use Firebase\JWT\Key as FirebaseKey;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256 as JoseES256;
use Jose\Component\Signature\Algorithm\HS256 as JoseHS256;
use Jose\Component\Signature\Algorithm\RS256 as JoseRS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JoseCompactSerializer;
use Lcobucci\JWT\Configuration as LcobucciConfig;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as LcEs256;
use Lcobucci\JWT\Signer\Hmac\Sha256 as LcHs256;
use Lcobucci\JWT\Signer\Key\InMemory as LcInMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as LcRs256;
use Lcobucci\JWT\Validation\Constraint\SignedWith as LcSignedWith;
use Medzuch\Jwt\Algorithm\Signing\Es256;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Benchmarks\Bench;
use Medzuch\Jwt\Benchmarks\Keys;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;

require __DIR__ . '/vendor/autoload.php';

const ISS = 'https://issuer.example';
const AUD = 'https://api.example';
const SUB = 'user-123';

$keys = new Keys();
$budget = (float) (getenv('BENCH_BUDGET') ?: '1.0');
$bench = new Bench(budgetSeconds: $budget);

$now = time();
$exp = $now + 900;

/** Logical claim set shared by every library. */
$claims = [
    'iss' => ISS,
    'sub' => SUB,
    'aud' => AUD,
    'iat' => $now,
    'exp' => $exp,
    'jti' => 'fixed-jti-for-benchmark',
    'scope' => 'documents:read documents:write',
];
$claimsJson = json_encode($claims, JSON_THROW_ON_ERROR);

// ---------------------------------------------------------------------------
// Per-library, per-algorithm reusable objects (built once).
// ---------------------------------------------------------------------------

// -- medzuch/jwt-php --
$oursAlg = ['HS256' => new Hs256(), 'RS256' => new Rs256(), 'ES256' => new Es256()];
$oursSignKey = [
    'HS256' => HmacKey::fromBinary($keys->hmacSecret, 'HS256', 'k'),
    'RS256' => RsaPrivateKey::fromPem($keys->rsaPrivatePem, 'RS256', 'k'),
    'ES256' => EcPrivateKey::fromPem($keys->ecPrivatePem, 'ES256', 'k'),
];
$oursVerifyKey = [
    'HS256' => HmacKey::fromBinary($keys->hmacSecret, 'HS256', 'k'),
    'RS256' => RsaPublicKey::fromPem($keys->rsaPublicPem, 'RS256', 'k'),
    'ES256' => EcPublicKey::fromPem($keys->ecPublicPem, 'ES256', 'k'),
];
// Mirrors what a real consumer does (and what the profile consumers set by
// default, e.g. AccessTokenProfile::consumer): algorithm allow-list, keys,
// issuer, audience, type, and required-claim enforcement. This is the full
// validation the docs attribute to the verify number — keep the two in sync.
$oursValidator = [];
foreach ($oursAlg as $name => $alg) {
    $oursValidator[$name] = ValidatorBuilder::create()
        ->expectAlgorithms([$alg])
        ->withKeys(JwkSet::of($oursVerifyKey[$name]))
        ->expectIssuer(ISS)
        ->expectAudience(AUD)
        ->expectType('JWT')
        ->requireClaims(['iss', 'sub', 'aud', 'exp', 'iat', 'jti'])
        ->build();
}

// -- firebase/php-jwt --
$fbSignKey = [
    'HS256' => $keys->hmacSecret,
    'RS256' => $keys->rsaPrivatePem,
    'ES256' => $keys->ecPrivatePem,
];
$fbVerifyKey = [
    'HS256' => new FirebaseKey($keys->hmacSecret, 'HS256'),
    'RS256' => new FirebaseKey($keys->rsaPublicPem, 'RS256'),
    'ES256' => new FirebaseKey($keys->ecPublicPem, 'ES256'),
];

// -- web-token/jwt-framework --
$joseAm = [
    'HS256' => new AlgorithmManager([new JoseHS256()]),
    'RS256' => new AlgorithmManager([new JoseRS256()]),
    'ES256' => new AlgorithmManager([new JoseES256()]),
];
$joseSignJwk = [
    'HS256' => JWKFactory::createFromSecret($keys->hmacSecret),
    'RS256' => JWKFactory::createFromKey($keys->rsaPrivatePem),
    'ES256' => JWKFactory::createFromKey($keys->ecPrivatePem),
];
$joseVerifyJwk = [
    'HS256' => JWKFactory::createFromSecret($keys->hmacSecret),
    'RS256' => JWKFactory::createFromKey($keys->rsaPublicPem),
    'ES256' => JWKFactory::createFromKey($keys->ecPublicPem),
];
$joseSerializer = new JoseCompactSerializer();
$joseBuilder = [];
$joseVerifier = [];
foreach (['HS256', 'RS256', 'ES256'] as $name) {
    $joseBuilder[$name] = new JWSBuilder($joseAm[$name]);
    $joseVerifier[$name] = new JWSVerifier($joseAm[$name]);
}

// -- lcobucci/jwt --
$lcConfig = [
    'HS256' => LcobucciConfig::forSymmetricSigner(new LcHs256(), LcInMemory::plainText($keys->hmacSecret)),
    'RS256' => LcobucciConfig::forAsymmetricSigner(new LcRs256(), LcInMemory::plainText($keys->rsaPrivatePem), LcInMemory::plainText($keys->rsaPublicPem)),
    'ES256' => LcobucciConfig::forAsymmetricSigner(new LcEs256(), LcInMemory::plainText($keys->ecPrivatePem), LcInMemory::plainText($keys->ecPublicPem)),
];
$lcIssuedAt = (new DateTimeImmutable())->setTimestamp($now);
$lcExpiresAt = (new DateTimeImmutable())->setTimestamp($exp);

// ---------------------------------------------------------------------------
// Issue closures.
// ---------------------------------------------------------------------------

$issuers = [];
foreach (['HS256', 'RS256', 'ES256'] as $name) {
    $issuers[$name]['medzuch/jwt-php'] = static function () use ($oursAlg, $oursSignKey, $name, $exp): string {
        return (string) JwtBuilder::create()
            ->type('JWT')
            ->issuer(ISS)->subject(SUB)->audience(AUD)
            ->issuedAtNow()->notBeforeNow()->expiresAt((new DateTimeImmutable())->setTimestamp($exp))
            ->jwtId('fixed-jti-for-benchmark')
            ->withClaim('scope', 'documents:read documents:write')
            ->signWith($oursAlg[$name], $oursSignKey[$name])
            ->build();
    };
    $issuers[$name]['firebase/php-jwt'] = static function () use ($claims, $fbSignKey, $name): string {
        return FirebaseJwt::encode($claims, $fbSignKey[$name], $name, 'k');
    };
    $issuers[$name]['web-token/jwt-framework'] = static function () use ($joseBuilder, $joseSerializer, $joseSignJwk, $claimsJson, $name): string {
        $jws = $joseBuilder[$name]->create()
            ->withPayload($claimsJson)
            ->addSignature($joseSignJwk[$name], ['alg' => $name])
            ->build();

        return $joseSerializer->serialize($jws, 0);
    };
    $issuers[$name]['lcobucci/jwt'] = static function () use ($lcConfig, $lcIssuedAt, $lcExpiresAt, $name): string {
        return $lcConfig[$name]->builder()
            ->issuedBy(ISS)->relatedTo(SUB)->permittedFor(AUD)
            ->issuedAt($lcIssuedAt)->expiresAt($lcExpiresAt)
            ->identifiedBy('fixed-jti-for-benchmark')
            ->withClaim('scope', 'documents:read documents:write')
            ->getToken($lcConfig[$name]->signer(), $lcConfig[$name]->signingKey())
            ->toString();
    };
}

// ---------------------------------------------------------------------------
// Verify closures (each library verifies a token it issued).
// ---------------------------------------------------------------------------

$verifiers = [];
foreach (['HS256', 'RS256', 'ES256'] as $name) {
    $oursToken = $issuers[$name]['medzuch/jwt-php']();
    $fbToken = $issuers[$name]['firebase/php-jwt']();
    $joseToken = $issuers[$name]['web-token/jwt-framework']();
    $lcToken = $issuers[$name]['lcobucci/jwt']();

    $verifiers[$name]['medzuch/jwt-php'] = static function () use ($oursValidator, $oursToken, $name): void {
        $oursValidator[$name]->validate(JwtParser::parse($oursToken));
    };
    $verifiers[$name]['firebase/php-jwt'] = static function () use ($fbVerifyKey, $fbToken, $name): void {
        FirebaseJwt::decode($fbToken, $fbVerifyKey[$name]);
    };
    $verifiers[$name]['web-token/jwt-framework'] = static function () use ($joseVerifier, $joseSerializer, $joseVerifyJwk, $joseToken, $name): void {
        $jws = $joseSerializer->unserialize($joseToken);
        if (!$joseVerifier[$name]->verifyWithKey($jws, $joseVerifyJwk[$name], 0)) {
            throw new RuntimeException('web-token verify returned false');
        }
    };
    $verifiers[$name]['lcobucci/jwt'] = static function () use ($lcConfig, $lcToken, $name): void {
        $token = $lcConfig[$name]->parser()->parse($lcToken);
        $constraint = new LcSignedWith($lcConfig[$name]->signer(), $lcConfig[$name]->verificationKey());
        if (!$lcConfig[$name]->validator()->validate($token, $constraint)) {
            throw new RuntimeException('lcobucci verify returned false');
        }
    };
}

// ---------------------------------------------------------------------------
// Run.
// ---------------------------------------------------------------------------

$libraries = ['medzuch/jwt-php', 'firebase/php-jwt', 'web-token/jwt-framework', 'lcobucci/jwt'];

fwrite(STDERR, "Running (budget {$budget}s/op)...\n");
foreach (['HS256', 'RS256', 'ES256'] as $name) {
    foreach ($libraries as $lib) {
        $bench->run("issue $name", $lib, $issuers[$name][$lib]);
        $bench->run("verify $name", $lib, $verifiers[$name][$lib]);
        fwrite(STDERR, "  done: $name $lib\n");
    }
}

require __DIR__ . '/report.php';
report($bench->results(), $libraries, PHP_VERSION);
