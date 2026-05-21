<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jws;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Hs384;
use Medzuch\Jwt\Exception\AlgorithmNotAllowedException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Exception\KeyNotFoundException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\ParsedJws;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Jws\Verifier;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyResolver;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\ConstantTime;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\Utf8;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

use function explode;
use function random_bytes;

#[CoversClass(Verifier::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(CompactJws::class)]
#[UsesClass(CompactSerializer::class)]
#[UsesClass(ParsedJws::class)]
#[UsesClass(Signer::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(Hs384::class)]
#[UsesClass(HmacAlgorithm::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(JwkSet::class)]
#[UsesClass(Key::class)]
#[UsesClass(KeyUse::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(StaticJwkSetResolver::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(ConstantTime::class)]
#[UsesClass(Json::class)]
#[UsesClass(Utf8::class)]
final class VerifierTest extends TestCase
{
    public function testVerifyRoundTrip(): void
    {
        $secret = random_bytes(32);
        $key = HmacKey::fromBinary($secret, 'HS256', kid: 'k1');
        $jws = (new Signer())->sign(new Hs256(), ['kid' => 'k1'], 'payload', $key);
        $parsed = CompactSerializer::deserialize($jws->value);

        $result = (new Verifier())->verify(
            $parsed,
            [new Hs256()],
            self::resolverFor($key),
        );

        self::assertSame($parsed, $result);
    }

    public function testVerifyRejectsAlgNotInAllowlist(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $jws = (new Signer())->sign(new Hs256(), ['kid' => 'k1'], 'payload', $key);
        $parsed = CompactSerializer::deserialize($jws->value);

        $this->expectException(AlgorithmNotAllowedException::class);
        $this->expectExceptionMessageMatches('/"HS256".*allowlist \[HS384\].*RFC 8725 §3\.1/');

        // Only HS384 is allowed; the token is HS256.
        (new Verifier())->verify($parsed, [new Hs384()], self::resolverFor($key));
    }

    public function testVerifyRejectsAlgNoneViaAllowlist(): void
    {
        // alg:none is just another value that fails the allowlist match —
        // the Verifier has no special case for it. (A real alg:none token
        // is additionally refused by CompactSerializer because its
        // signature segment is empty; see CompactSerializerTest.)
        $parsed = self::manualParsedJws(['alg' => 'none'], 'payload', 'fake-signature');

        $this->expectException(AlgorithmNotAllowedException::class);
        $this->expectExceptionMessageMatches('/"none".*RFC 8725 §3\.1/');

        (new Verifier())->verify(
            $parsed,
            [new Hs256()],
            self::resolverFor(HmacKey::fromBinary(random_bytes(32), 'HS256')),
        );
    }

    public function testAlgNoneCompactFormIsRefusedAtParse(): void
    {
        $this->expectException(\Medzuch\Jwt\Exception\MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/signature segment is empty/');

        CompactSerializer::deserialize(self::compactWithEmptySignature(['alg' => 'none'], 'payload'));
    }

    public function testVerifyRefusesCritHeader(): void
    {
        // crit is structurally valid but Verifier refuses any value
        // because Phase 1 understands no extensions.
        $jws = self::manualJws(['alg' => 'HS256', 'crit' => ['b64']], 'payload', "\x00");
        $parsed = CompactSerializer::deserialize($jws);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/declares "crit".*understands none/');

        (new Verifier())->verify(
            $parsed,
            [new Hs256()],
            self::resolverFor(HmacKey::fromBinary(random_bytes(32), 'HS256')),
        );
    }

    public function testVerifyRefusesB64Header(): void
    {
        $jws = self::manualJws(['alg' => 'HS256', 'b64' => false], 'payload', "\x00");
        $parsed = CompactSerializer::deserialize($jws);

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/declares "b64".*Phase 4/');

        (new Verifier())->verify(
            $parsed,
            [new Hs256()],
            self::resolverFor(HmacKey::fromBinary(random_bytes(32), 'HS256')),
        );
    }

    public function testVerifyRejectsTamperedPayloadAsBadSignature(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $signed = (new Signer())->sign(new Hs256(), ['kid' => 'k1'], 'original', $key);

        // Replace the payload segment with bytes that decode to "tampered".
        [$h, , $s] = explode('.', $signed->value);
        $tampered = $h . '.' . Base64Url::encode('tampered') . '.' . $s;
        $parsed = CompactSerializer::deserialize($tampered);

        $this->expectException(SignatureVerificationException::class);
        $this->expectExceptionMessageMatches('/did not verify under algorithm HS256/');

        (new Verifier())->verify($parsed, [new Hs256()], self::resolverFor($key));
    }

    public function testVerifyPropagatesKeyMismatchFromAlgorithm(): void
    {
        // McLean-direction reverse: header says HS256, allowlist allows
        // HS256, but the resolver returns a key bound to HS384 — the
        // algorithm strategy's assertAlgorithm refuses it.
        $tokenSigner = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $jws = (new Signer())->sign(new Hs256(), ['kid' => 'k1'], 'payload', $tokenSigner);
        $parsed = CompactSerializer::deserialize($jws->value);

        $wrongAlgKey = HmacKey::fromBinary(random_bytes(48), 'HS384', kid: 'k1');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/HS384.*HS256/');

        (new Verifier())->verify($parsed, [new Hs256()], self::resolverFor($wrongAlgKey));
    }

    public function testVerifyPropagatesKeyNotFound(): void
    {
        $jws = (new Signer())->sign(
            new Hs256(),
            ['kid' => 'unknown-kid'],
            'payload',
            HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'unknown-kid'),
        );
        $parsed = CompactSerializer::deserialize($jws->value);

        $emptyResolver = new StaticJwkSetResolver(JwkSet::of());

        $this->expectException(KeyNotFoundException::class);

        (new Verifier())->verify($parsed, [new Hs256()], $emptyResolver);
    }

    public function testFirstMatchingAlgorithmInAllowlistWins(): void
    {
        // If two strategies in the allowlist report the same name (a
        // programming error, but representable), the first one wins.
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256', kid: 'k1');
        $jws = (new Signer())->sign(new Hs256(), ['kid' => 'k1'], 'payload', $key);
        $parsed = CompactSerializer::deserialize($jws->value);

        $first = new Hs256();
        $second = new Hs256();

        $result = (new Verifier())->verify($parsed, [$first, $second], self::resolverFor($key));

        self::assertSame($parsed, $result);
    }

    private static function resolverFor(Key $key): KeyResolver
    {
        return new StaticJwkSetResolver(JwkSet::of($key));
    }

    /**
     * Build a compact JWS bypassing Signer so we can attach unusual
     * headers (crit, b64) that Signer would normally not produce.
     *
     * @param array<string, mixed> $header
     */
    private static function manualJws(array $header, string $payload, string $signature): string
    {
        $encodedHeader = Base64Url::encode(Json::encode($header));
        $encodedPayload = Base64Url::encode($payload);
        $encodedSignature = Base64Url::encode($signature);

        return $encodedHeader . '.' . $encodedPayload . '.' . $encodedSignature;
    }

    /**
     * @param array<string, mixed> $header
     */
    private static function compactWithEmptySignature(array $header, string $payload): string
    {
        $encodedHeader = Base64Url::encode(Json::encode($header));
        $encodedPayload = Base64Url::encode($payload);

        return $encodedHeader . '.' . $encodedPayload . '.';
    }

    /**
     * @param array<string, mixed> $header
     */
    private static function manualParsedJws(array $header, string $payload, string $signature): ParsedJws
    {
        $encodedHeader = Base64Url::encode(Json::encode($header));
        $encodedPayload = Base64Url::encode($payload);
        $encodedSignature = Base64Url::encode($signature);

        return new ParsedJws(
            $encodedHeader,
            $encodedPayload,
            $encodedSignature,
            $header,
            $payload,
            $signature,
        );
    }
}
