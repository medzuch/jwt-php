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

    /** @return iterable<string, array{string}> */
    public static function applicationPrefixedValues(): iterable
    {
        yield 'lowercase prefix' => ['application/at+jwt'];
        yield 'mixed-case prefix' => ['Application/AT+JWT'];
    }

    #[DataProvider('applicationPrefixedValues')]
    public function testCustomRejectsApplicationPrefix(string $value): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('MediaType value must omit the "application/" prefix (RFC 7515 §4.1.9)');

        MediaType::custom($value);
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

    public function testToStringEqualsValue(): void
    {
        self::assertSame('at+jwt', (string) MediaType::accessToken());
    }

    /**
     * Wire-level equivalence per RFC 7515 §4.1.9: case-insensitive, with the
     * `application/` prefix optional on either side.
     */
    #[DataProvider('equivalencePairs')]
    public function testEquivalent(string $a, string $b, bool $expected): void
    {
        self::assertSame($expected, MediaType::equivalent($a, $b));
        // Documented as a symmetric relation.
        self::assertSame($expected, MediaType::equivalent($b, $a));
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: bool}>
     */
    public static function equivalencePairs(): iterable
    {
        yield 'identical' => ['at+jwt', 'at+jwt', true];
        yield 'case-insensitive, no prefix' => ['AT+JWT', 'at+jwt', true];
        yield 'prefix on one side' => ['application/at+jwt', 'at+jwt', true];
        // Uppercase prefix must still be recognised (the prefix test lowercases).
        yield 'uppercase prefix' => ['APPLICATION/at+jwt', 'at+jwt', true];
        // Prefix stripped on one side, case folded on the other.
        yield 'prefix plus case fold' => ['application/at+jwt', 'AT+JWT', true];
        yield 'prefix on both sides' => ['application/at+jwt', 'application/at+jwt', true];
        // The prefix branch used to slice the original string, so the subtype
        // kept its case and only the folded-on-both-sides spellings matched.
        // `application/at+jwt` is the type RFC 9068 §4 registers for an access
        // token; RFC 7515 §4.1.9 makes the case insignificant, so a producer
        // may legitimately send any case variant of it.
        //
        // These rows carry the prefix on ONE side only, so they cannot be
        // satisfied by the `strcasecmp()` fast path and must reach the
        // normaliser — that is what makes them a regression test. A row with
        // the prefix on both sides is always equal ignoring case and returns
        // early, so it would stay green against the old implementation.
        yield 'uppercase subtype behind prefix' => ['application/AT+JWT', 'at+jwt', true];
        yield 'uppercase prefix and subtype' => ['APPLICATION/AT+JWT', 'at+jwt', true];
        yield 'mixed case either side of the prefix' => ['Application/At+Jwt', 'aT+jWt', true];
        // The `cty` marker on a nested JWT (RFC 7519 §5.2), long form.
        yield 'legacy JWT behind uppercase prefix' => ['APPLICATION/JWT', 'JWT', true];
        yield 'legacy JWT behind prefix, mixed case' => ['application/JWT', 'jwt', true];
        // Only one prefix is stripped — a subtype that itself looks like a
        // prefixed name is not folded down to the bare form.
        yield 'doubled prefix is not stripped twice' => ['application/application/jwt', 'application/jwt', false];
        yield 'different subtypes' => ['at+jwt', 'id+jwt', false];
        yield 'different subtypes with prefix' => ['application/at+jwt', 'application/id+jwt', false];
    }
}
