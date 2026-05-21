<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jws;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jws\CompactSerializer;
use Medzuch\Jwt\Jws\ParsedJws;
use Medzuch\Jwt\Jws\Signer;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\ConstantTime;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Primitives\Utf8;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Signer::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(CompactJws::class)]
#[UsesClass(CompactSerializer::class)]
#[UsesClass(ParsedJws::class)]
#[UsesClass(Hs256::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\Signing\HmacAlgorithm::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(Key::class)]
#[UsesClass(KeyUse::class)]
#[UsesClass(JwkAttributes::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(ConstantTime::class)]
#[UsesClass(Json::class)]
#[UsesClass(Utf8::class)]
final class SignerTest extends TestCase
{
    public function testSignFillsAlgHeaderAndProducesVerifiableSignature(): void
    {
        $signer = new Signer();
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $jws = $signer->sign($algo, ['kid' => 'k1', 'typ' => 'JWT'], '{"sub":"u"}', $key);

        $parsed = CompactSerializer::deserialize($jws->value);

        self::assertSame('HS256', $parsed->header['alg']);
        self::assertSame('k1', $parsed->header['kid']);
        self::assertSame('JWT', $parsed->header['typ']);
        self::assertSame('{"sub":"u"}', $parsed->payload);
        self::assertTrue($algo->verify($parsed->signingInput(), $parsed->signature, $key));
    }

    public function testSignAcceptsCallerProvidedAlgWhenItAgrees(): void
    {
        $signer = new Signer();
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $jws = $signer->sign($algo, ['alg' => 'HS256', 'kid' => 'k1'], 'payload', $key);

        $parsed = CompactSerializer::deserialize($jws->value);

        self::assertSame('HS256', $parsed->header['alg']);
    }

    public function testSignRejectsConflictingAlgInHeader(): void
    {
        $signer = new Signer();
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/"HS384".*does not match.*HS256/');

        $signer->sign($algo, ['alg' => 'HS384'], 'payload', $key);
    }

    public function testSignRejectsNonStringAlgInHeader(): void
    {
        $signer = new Signer();
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/\(int\).*does not match.*HS256/');

        $signer->sign($algo, ['alg' => 42], 'payload', $key);
    }

    public function testSignRejectsNullAlgInHeader(): void
    {
        $signer = new Signer();
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessageMatches('/null.*does not match.*HS256/');

        $signer->sign($algo, ['alg' => null], 'payload', $key);
    }

    public function testSignPropagatesKeyMismatchFromAlgorithm(): void
    {
        // Key bound to HS384 cannot sign for HS256; the algorithm layer
        // throws KeyMismatchException and the Signer does not swallow it.
        $signer = new Signer();
        $algo = new Hs256();
        $wrongAlgKey = HmacKey::fromBinary(random_bytes(48), 'HS384');

        $this->expectException(KeyMismatchException::class);

        $signer->sign($algo, [], 'payload', $wrongAlgKey);
    }

    public function testSignWithEmptyPayloadStillProducesValidJws(): void
    {
        $signer = new Signer();
        $algo = new Hs256();
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $jws = $signer->sign($algo, [], '', $key);
        $parsed = CompactSerializer::deserialize($jws->value);

        self::assertSame('', $parsed->payload);
        self::assertTrue($algo->verify($parsed->signingInput(), $parsed->signature, $key));
    }
}
