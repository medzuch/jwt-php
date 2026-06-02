<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwe\Internal;

use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jwe\Internal\JweHeader;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Direct shape checks for the effective JWE JOSE header. Both the compact and
 * JSON serializers lean on {@see JweHeader::assertShape}; exercising every
 * branch here pins the fail-closed `crit`/`zip`/`b64` refusals down on their
 * own rather than only incidentally through the serializers.
 */
#[CoversClass(JweHeader::class)]
final class JweHeaderTest extends TestCase
{
    public function testAcceptsAMinimalValidHeader(): void
    {
        JweHeader::assertShape(['alg' => 'A128KW', 'enc' => 'A128GCM']);

        $this->expectNotToPerformAssertions();
    }

    public function testAcceptsOptionalStringMembers(): void
    {
        JweHeader::assertShape([
            'alg' => 'A128KW',
            'enc' => 'A128GCM',
            'typ' => 'JWT',
            'cty' => 'example+json',
            'kid' => 'key-1',
        ]);

        $this->expectNotToPerformAssertions();
    }

    /**
     * @param array<string, mixed> $header
     */
    #[DataProvider('missingRequiredProvider')]
    public function testRejectsMissingRequiredMember(array $header, string $missing): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage(sprintf('missing required "%s"', $missing));

        JweHeader::assertShape($header);
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function missingRequiredProvider(): iterable
    {
        yield 'no alg' => [['enc' => 'A128GCM'], 'alg'];
        yield 'no enc' => [['alg' => 'A128KW'], 'enc'];
    }

    /**
     * @param array<string, mixed> $header
     */
    #[DataProvider('nonStringRequiredProvider')]
    public function testRejectsNonStringOrEmptyRequiredMember(array $header, string $member): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage(sprintf('"%s" must be a non-empty string', $member));

        JweHeader::assertShape($header);
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function nonStringRequiredProvider(): iterable
    {
        yield 'alg empty' => [['alg' => '', 'enc' => 'A128GCM'], 'alg'];
        yield 'alg integer' => [['alg' => 42, 'enc' => 'A128GCM'], 'alg'];
        yield 'alg null' => [['alg' => null, 'enc' => 'A128GCM'], 'alg'];
        yield 'enc empty' => [['alg' => 'A128KW', 'enc' => ''], 'enc'];
        yield 'enc integer' => [['alg' => 'A128KW', 'enc' => 7], 'enc'];
        yield 'enc null' => [['alg' => 'A128KW', 'enc' => null], 'enc'];
    }

    public function testRejectsCrit(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('declares "crit" extensions');

        JweHeader::assertShape(['alg' => 'A128KW', 'enc' => 'A128GCM', 'crit' => ['exp']]);
    }

    public function testRejectsCritDeclaredAsNull(): void
    {
        // array_key_exists, not isset: an explicit null still counts as declared.
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('declares "crit" extensions');

        JweHeader::assertShape(['alg' => 'A128KW', 'enc' => 'A128GCM', 'crit' => null]);
    }

    public function testRejectsZip(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('declares "zip"');

        JweHeader::assertShape(['alg' => 'A128KW', 'enc' => 'A128GCM', 'zip' => 'DEF']);
    }

    public function testRejectsB64(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('declares "b64"');

        JweHeader::assertShape(['alg' => 'A128KW', 'enc' => 'A128GCM', 'b64' => false]);
    }

    /**
     * @param array<string, mixed> $header
     */
    #[DataProvider('nonStringOptionalProvider')]
    public function testRejectsNonStringOptionalMember(array $header, string $member): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage(sprintf('"%s" must be a string when present', $member));

        JweHeader::assertShape($header);
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function nonStringOptionalProvider(): iterable
    {
        $base = ['alg' => 'A128KW', 'enc' => 'A128GCM'];

        yield 'typ integer' => [$base + ['typ' => 1], 'typ'];
        yield 'cty array' => [$base + ['cty' => []], 'cty'];
        yield 'kid integer' => [$base + ['kid' => 42], 'kid'];
    }
}
