<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwt;

use LogicException;
use Medzuch\Jwt\Jwt\MediaType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(MediaType::class)]
final class MediaTypeTest extends TestCase
{
    /** @return iterable<string, array{MediaType, string}> */
    public static function registeredMediaTypes(): iterable
    {
        yield 'JWT' => [MediaType::jwt(), 'JWT'];
        yield 'at+jwt' => [MediaType::accessToken(), 'at+jwt'];
        yield 'id+jwt' => [MediaType::idToken(), 'id+jwt'];
        yield 'secevent+jwt' => [MediaType::securityEventToken(), 'secevent+jwt'];
    }

    #[DataProvider('registeredMediaTypes')]
    public function testRegisteredFactoriesExposeExpectedValue(MediaType $mt, string $expected): void
    {
        self::assertSame($expected, $mt->value);
        self::assertSame($expected, (string) $mt);
    }

    public function testCustomAcceptsArbitraryValue(): void
    {
        $mt = MediaType::custom('dpop+jwt');

        self::assertSame('dpop+jwt', $mt->value);
    }

    public function testCustomRejectsEmptyValue(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('MediaType value cannot be empty');

        MediaType::custom('');
    }

    public function testCustomAcceptsNamesWithoutJwtSuffix(): void
    {
        // The library does not enforce the "+jwt" suffix so application-private
        // or transitional names remain expressible.
        $mt = MediaType::custom('vendor.example.session');

        self::assertSame('vendor.example.session', $mt->value);
    }

    public function testInstancesWithSameValueAreEqualByPropertyComparison(): void
    {
        self::assertEquals(MediaType::accessToken(), MediaType::accessToken());
        self::assertEquals(MediaType::accessToken(), MediaType::custom('at+jwt'));
        self::assertNotEquals(MediaType::accessToken(), MediaType::idToken());
    }
}
