<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jws\Internal;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jws\Internal\HeaderShape;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Direct shape checks for the integrity-protected JOSE header. The compact
 * and JSON deserializers both lean on {@see HeaderShape::assertProtected};
 * this exercises every branch so a mutant that drops a check is caught here
 * rather than only incidentally through the serializer suites.
 */
#[CoversClass(HeaderShape::class)]
final class HeaderShapeTest extends TestCase
{
    public function testAcceptsAMinimalValidHeader(): void
    {
        HeaderShape::assertProtected(['alg' => 'HS256']);

        $this->expectNotToPerformAssertions();
    }

    public function testAcceptsTypedStringMembers(): void
    {
        HeaderShape::assertProtected([
            'alg' => 'HS256',
            'typ' => 'JWT',
            'cty' => 'example+json',
            'kid' => 'key-1',
        ]);

        $this->expectNotToPerformAssertions();
    }

    public function testRejectsMissingAlg(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('missing required "alg"');

        HeaderShape::assertProtected(['kid' => 'k1']);
    }

    /**
     * @param array<string, mixed> $header
     */
    #[DataProvider('nonStringOrEmptyAlgProvider')]
    public function testRejectsAlgThatIsNotANonEmptyString(array $header): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"alg" must be a non-empty string');

        HeaderShape::assertProtected($header);
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function nonStringOrEmptyAlgProvider(): iterable
    {
        yield 'empty string' => [['alg' => '']];
        yield 'integer' => [['alg' => 256]];
        yield 'boolean' => [['alg' => true]];
        yield 'array' => [['alg' => ['HS256']]];
        yield 'explicit null' => [['alg' => null]];
    }

    /**
     * @param array<string, mixed> $header
     */
    #[DataProvider('nonStringTypedMemberProvider')]
    public function testRejectsNonStringTypedMember(array $header, string $expectedMember): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage(sprintf('"%s" must be a string when present', $expectedMember));

        HeaderShape::assertProtected($header);
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function nonStringTypedMemberProvider(): iterable
    {
        // `array_key_exists`, not `isset`, so an explicit null must fail the
        // type check rather than being treated as absent.
        yield 'typ integer' => [['alg' => 'HS256', 'typ' => 1], 'typ'];
        yield 'typ null' => [['alg' => 'HS256', 'typ' => null], 'typ'];
        yield 'cty array' => [['alg' => 'HS256', 'cty' => []], 'cty'];
        yield 'cty null' => [['alg' => 'HS256', 'cty' => null], 'cty'];
        yield 'kid integer' => [['alg' => 'HS256', 'kid' => 42], 'kid'];
        yield 'kid null' => [['alg' => 'HS256', 'kid' => null], 'kid'];
    }
}
