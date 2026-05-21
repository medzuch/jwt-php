<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwt;

use Medzuch\Jwt\Exception\ClaimTypeException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ClaimsSet::class)]
final class ClaimsSetTest extends TestCase
{
    public function testRegisteredAccessors(): void
    {
        $c = new ClaimsSet([
            'iss' => 'https://issuer.example',
            'sub' => 'user-1',
            'aud' => 'https://api.example',
            'exp' => 1_300_819_380,
            'nbf' => 1_300_819_300,
            'iat' => 1_300_819_280,
            'jti' => 'id-1',
        ]);

        self::assertSame('https://issuer.example', $c->issuer());
        self::assertSame('user-1', $c->subject());
        self::assertSame(['https://api.example'], $c->audience());
        self::assertSame(1_300_819_380, $c->expiresAt()?->getTimestamp());
        self::assertSame(1_300_819_300, $c->notBefore()?->getTimestamp());
        self::assertSame(1_300_819_280, $c->issuedAt()?->getTimestamp());
        self::assertSame('id-1', $c->jwtId());
    }

    public function testAudienceListIsPassedThrough(): void
    {
        $c = new ClaimsSet(['aud' => ['a', 'b']]);

        self::assertSame(['a', 'b'], $c->audience());
    }

    public function testAudienceMissingReturnsEmptyList(): void
    {
        self::assertSame([], (new ClaimsSet([]))->audience());
    }

    public function testAudienceRejectsNonStringEntry(): void
    {
        $this->expectException(ClaimTypeException::class);
        $this->expectExceptionMessageMatches('/"aud".*only strings/');

        (new ClaimsSet(['aud' => ['a', 42]]))->audience();
    }

    public function testAudienceRejectsNonStringNonArray(): void
    {
        $this->expectException(ClaimTypeException::class);
        $this->expectExceptionMessageMatches('/"aud".*string or list/');

        (new ClaimsSet(['aud' => 42]))->audience();
    }

    public function testTypedAccessors(): void
    {
        $c = new ClaimsSet(['s' => 'x', 'i' => 42, 'b' => true, 'l' => ['a', 'b']]);

        self::assertSame('x', $c->getString('s'));
        self::assertSame(42, $c->getInt('i'));
        self::assertTrue($c->getBool('b'));
        self::assertSame(['a', 'b'], $c->getList('l'));
    }

    public function testTypedAccessorsReturnNullForMissing(): void
    {
        $c = new ClaimsSet([]);

        self::assertNull($c->getString('x'));
        self::assertNull($c->getInt('x'));
        self::assertNull($c->getBool('x'));
        self::assertNull($c->getList('x'));
    }

    public function testGetStringRejectsNonString(): void
    {
        $this->expectException(ClaimTypeException::class);

        (new ClaimsSet(['x' => 42]))->getString('x');
    }

    public function testGetIntRejectsNonInt(): void
    {
        $this->expectException(ClaimTypeException::class);

        (new ClaimsSet(['x' => '42']))->getInt('x');
    }

    public function testGetBoolRejectsNonBool(): void
    {
        $this->expectException(ClaimTypeException::class);

        (new ClaimsSet(['x' => 1]))->getBool('x');
    }

    public function testGetListRejectsAssocArray(): void
    {
        $this->expectException(ClaimTypeException::class);
        $this->expectExceptionMessageMatches('/list of strings/');

        (new ClaimsSet(['x' => ['k' => 'v']]))->getList('x');
    }

    public function testGetListRejectsNonString(): void
    {
        $this->expectException(ClaimTypeException::class);

        (new ClaimsSet(['x' => ['a', 42]]))->getList('x');
    }

    public function testTimestampAccessorRejectsNonInt(): void
    {
        $this->expectException(ClaimTypeException::class);
        $this->expectExceptionMessageMatches('/NumericDate/');

        (new ClaimsSet(['exp' => '1300819380']))->expiresAt();
    }

    public function testHasAndGet(): void
    {
        $c = new ClaimsSet(['x' => 42]);

        self::assertTrue($c->has('x'));
        self::assertFalse($c->has('y'));
        self::assertSame(42, $c->get('x'));
        self::assertNull($c->get('y'));
    }
}
