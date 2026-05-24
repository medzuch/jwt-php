<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key\Internal;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\JwkAttributes;
use Medzuch\Jwt\Key\KeyUse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(JwkAttributes::class)]
#[UsesClass(KeyUse::class)]
final class JwkAttributesTest extends TestCase
{
    public function testRequireStringReturnsValue(): void
    {
        self::assertSame('RSA', JwkAttributes::requireString(['kty' => 'RSA'], 'kty'));
    }

    public function testRequireStringRejectsMissing(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/missing required "kty"/');

        JwkAttributes::requireString([], 'kty');
    }

    public function testRequireStringRejectsNonString(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"kty" must be a non-empty string/');

        JwkAttributes::requireString(['kty' => 42], 'kty');
    }

    public function testRequireStringRejectsEmptyString(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"kty" must be a non-empty string/');

        JwkAttributes::requireString(['kty' => ''], 'kty');
    }

    public function testOptionalStringReturnsNullWhenMissing(): void
    {
        self::assertNull(JwkAttributes::optionalString([], 'kid'));
    }

    public function testOptionalStringReturnsValueWhenPresent(): void
    {
        self::assertSame('k1', JwkAttributes::optionalString(['kid' => 'k1'], 'kid'));
    }

    public function testOptionalStringRejectsNonString(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"kid" must be a non-empty string/');

        JwkAttributes::optionalString(['kid' => 99], 'kid');
    }

    public function testOptionalStringRejectsEmptyString(): void
    {
        $this->expectException(InvalidKeyException::class);

        JwkAttributes::optionalString(['kid' => ''], 'kid');
    }

    public function testOptionalKeyUseReturnsNullWhenMissing(): void
    {
        self::assertNull(JwkAttributes::optionalKeyUse([]));
    }

    public function testOptionalKeyUseParsesSig(): void
    {
        self::assertSame(KeyUse::Sig, JwkAttributes::optionalKeyUse(['use' => 'sig']));
    }

    public function testOptionalKeyUseRejectsUnknownValue(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/"use" must be "sig" or "enc"/');

        JwkAttributes::optionalKeyUse(['use' => 'banana']);
    }

    public function testOptionalKeyOpsReturnsNullWhenMissing(): void
    {
        self::assertNull(JwkAttributes::optionalKeyOps([]));
    }

    public function testOptionalKeyOpsReturnsList(): void
    {
        self::assertSame(['sign', 'verify'], JwkAttributes::optionalKeyOps(['key_ops' => ['sign', 'verify']]));
    }

    public function testOptionalKeyOpsRejectsNonArray(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/key_ops.*JSON array of strings/');

        JwkAttributes::optionalKeyOps(['key_ops' => 'sign']);
    }

    public function testOptionalKeyOpsRejectsAssociativeArray(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/key_ops.*JSON array of strings/');

        JwkAttributes::optionalKeyOps(['key_ops' => ['op' => 'sign']]);
    }

    public function testOptionalKeyOpsRejectsNonStringEntry(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/entries must be non-empty strings/');

        JwkAttributes::optionalKeyOps(['key_ops' => ['sign', 99]]);
    }

    public function testOptionalKeyOpsRejectsEmptyStringEntry(): void
    {
        $this->expectException(InvalidKeyException::class);

        JwkAttributes::optionalKeyOps(['key_ops' => ['sign', '']]);
    }
}
