<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jws\Internal;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jws\Internal\B64Header;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Direct tests for the `b64`/`crit` coupling (RFC 7797 + RFC 7515 §4.1.11).
 * Both the compact and JSON JWS paths lean on {@see B64Header::assertValid};
 * exercising every rule here pins the helper down on its own rather than
 * only incidentally through the two serializers.
 */
#[CoversClass(B64Header::class)]
final class B64HeaderTest extends TestCase
{
    /**
     * @param array<string, mixed> $header
     */
    #[DataProvider('validHeaderProvider')]
    public function testAcceptsValidHeaders(array $header): void
    {
        B64Header::assertValid($header);

        $this->expectNotToPerformAssertions();
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function validHeaderProvider(): iterable
    {
        yield 'empty header' => [[]];
        yield 'no b64, no crit' => [['alg' => 'HS256']];
        yield 'b64 true without crit' => [['alg' => 'HS256', 'b64' => true]];
        yield 'b64 true with crit b64' => [['alg' => 'HS256', 'b64' => true, 'crit' => ['b64']]];
        yield 'b64 false with crit b64' => [['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']]];
        // A multi-element (here duplicate) crit list is structurally valid —
        // RFC 7515 §4.1.11 does not forbid repeats — and exercises the
        // sequential-key advancement in isNonEmptyStringList past one entry.
        yield 'b64 false with duplicate crit b64' => [['alg' => 'HS256', 'b64' => false, 'crit' => ['b64', 'b64']]];
    }

    /**
     * @param array<string, mixed> $header
     */
    #[DataProvider('nonBooleanB64Provider')]
    public function testRejectsNonBooleanB64(array $header): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"b64" must be a boolean');

        B64Header::assertValid($header);
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function nonBooleanB64Provider(): iterable
    {
        yield 'string' => [['b64' => 'false']];
        yield 'integer 0' => [['b64' => 0]];
        yield 'integer 1' => [['b64' => 1]];
        yield 'null' => [['b64' => null]];
        yield 'array' => [['b64' => [false]]];
    }

    /**
     * @param mixed $crit
     */
    #[DataProvider('malformedCritProvider')]
    public function testRejectsCritThatIsNotANonEmptyStringList(mixed $crit): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"crit" must be a non-empty list of non-empty strings');

        B64Header::assertValid(['alg' => 'HS256', 'b64' => false, 'crit' => $crit]);
    }

    /**
     * @return iterable<string, array{0: mixed}>
     */
    public static function malformedCritProvider(): iterable
    {
        yield 'not an array' => ['b64'];
        yield 'empty array' => [[]];
        yield 'non-string entry' => [[42]];
        yield 'empty-string entry' => [['']];
        yield 'non-list (assoc)' => [['0' => 'b64', 'x' => 'b64']];
        yield 'non-sequential keys' => [[1 => 'b64']];
    }

    public function testRejectsCritListingUnsupportedExtension(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('unsupported extension "exp"');

        B64Header::assertValid(['alg' => 'HS256', 'b64' => true, 'crit' => ['exp']]);
    }

    public function testRejectsCritListingB64ButHeaderMissingB64(): void
    {
        // crit:["b64"] is only meaningful when `b64` is itself a member.
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"b64" header parameter is not present');

        B64Header::assertValid(['alg' => 'HS256', 'crit' => ['b64']]);
    }

    public function testRejectsB64FalseWithoutCrit(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"b64":false requires "crit" to include "b64"');

        B64Header::assertValid(['alg' => 'HS256', 'b64' => false]);
    }
}
