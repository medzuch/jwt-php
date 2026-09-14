<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Jwt;

use LogicException;
use Medzuch\Jwt\Exception\ClaimTypeException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\Confirmation;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Confirmation::class)]
#[CoversClass(ClaimsSet::class)]
#[UsesClass(Base64Url::class)]
#[UsesClass(MalformedJwtException::class)]
final class ConfirmationTest extends TestCase
{
    /** RFC 7638 §3.1 thumbprint — any well-formed SHA-256 digest would do. */
    private const JKT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    /** RFC 9449 §6.1 example `jkt` — used here only as a second well-formed digest. */
    private const X5T_S256 = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';

    /**
     * RFC 8705 §3.1 / §3.2 example `x5t#S256`. It is 43 characters, but its
     * last one leaves non-zero padding bits, so no base64url encoder emits
     * it and no certificate's thumbprint can ever equal it.
     */
    private const RFC8705_EXAMPLE = 'bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2';

    public function testJwkThumbprintCarriesJktOnly(): void
    {
        $confirmation = Confirmation::jwkThumbprint(self::JKT);

        self::assertSame(self::JKT, $confirmation->jkt());
        self::assertNull($confirmation->x5tS256());
        self::assertSame(['jkt' => self::JKT], $confirmation->toClaim());
    }

    public function testCertificateThumbprintCarriesX5tS256Only(): void
    {
        $confirmation = Confirmation::certificateThumbprint(self::X5T_S256);

        self::assertSame(self::X5T_S256, $confirmation->x5tS256());
        self::assertNull($confirmation->jkt());
        self::assertSame(['x5t#S256' => self::X5T_S256], $confirmation->toClaim());
    }

    /** @return iterable<string, array{string}> */
    public static function malformedThumbprintProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'hex digest' => [hash('sha256', 'certificate')];
        yield 'padded base64url' => [self::JKT . '='];
        yield 'standard base64 alphabet' => [strtr(self::JKT, '-_', '+/')];
        yield 'SHA-1 length' => [Base64Url::encode(sha1('certificate', true))];
        yield 'SHA-512 length' => [Base64Url::encode(hash('sha512', 'certificate', true))];
        yield 'non-canonical trailing bits' => [substr(self::JKT, 0, -1) . 't'];
        yield 'RFC 8705 example value' => [self::RFC8705_EXAMPLE];
    }

    #[DataProvider('malformedThumbprintProvider')]
    public function testJwkThumbprintRefusesMalformedValue(string $value): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('"jkt"');

        Confirmation::jwkThumbprint($value);
    }

    #[DataProvider('malformedThumbprintProvider')]
    public function testCertificateThumbprintRefusesMalformedValue(string $value): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('"x5t#S256"');

        Confirmation::certificateThumbprint($value);
    }

    public function testClaimsSetWithoutCnfHasNoConfirmation(): void
    {
        self::assertNull((new ClaimsSet(['sub' => 'user-1']))->confirmation());
    }

    public function testClaimsSetReadsJkt(): void
    {
        $confirmation = (new ClaimsSet(['cnf' => ['jkt' => self::JKT]]))->confirmation();

        self::assertNotNull($confirmation);
        self::assertSame(self::JKT, $confirmation->jkt());
        self::assertNull($confirmation->x5tS256());
    }

    public function testClaimsSetReadsX5tS256(): void
    {
        $confirmation = (new ClaimsSet(['cnf' => ['x5t#S256' => self::X5T_S256]]))->confirmation();

        self::assertNotNull($confirmation);
        self::assertSame(self::X5T_S256, $confirmation->x5tS256());
        self::assertNull($confirmation->jkt());
    }

    /**
     * RFC 7800 §3.1: members that are not understood MUST be ignored.
     *
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function unmodelledCnfProvider(): iterable
    {
        yield 'jwk' => [['jwk' => ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'AQAB', 'y' => 'AQAB']]];
        yield 'jwe' => [['jwe' => 'eyJhbGciOiJSU0EtT0FFUCJ9.a.b.c.d']];
        yield 'jku and kid' => [['jku' => 'https://client.example/jwks', 'kid' => 'k1']];
        yield 'member from a future specification' => [['x-future' => ['nested' => true]]];
        yield 'empty object' => [[]];
    }

    /** @param array<string, mixed> $cnf */
    #[DataProvider('unmodelledCnfProvider')]
    public function testUnmodelledMembersParseToAnEmptyConfirmation(array $cnf): void
    {
        $confirmation = (new ClaimsSet(['cnf' => $cnf]))->confirmation();

        self::assertNotNull($confirmation, 'a present cnf must stay distinguishable from an absent one');
        self::assertNull($confirmation->jkt());
        self::assertNull($confirmation->x5tS256());
    }

    public function testUnmodelledMembersBesideModelledOnesAreIgnored(): void
    {
        $confirmation = (new ClaimsSet(['cnf' => ['kid' => 'k1', 'jkt' => self::JKT, 'x-future' => 1]]))->confirmation();

        self::assertNotNull($confirmation);
        self::assertSame(self::JKT, $confirmation->jkt());
        self::assertSame(['jkt' => self::JKT], $confirmation->toClaim());
    }

    public function testBothModelledMembersAreReadWhenAForeignTokenCarriesThem(): void
    {
        $confirmation = (new ClaimsSet(['cnf' => ['jkt' => self::JKT, 'x5t#S256' => self::X5T_S256]]))->confirmation();

        self::assertNotNull($confirmation);
        self::assertSame(['jkt' => self::JKT, 'x5t#S256' => self::X5T_S256], $confirmation->toClaim());
    }

    public function testToClaimRefusesAConfirmationWithNothingToWrite(): void
    {
        $confirmation = (new ClaimsSet(['cnf' => ['jku' => 'https://client.example/jwks']]))->confirmation();
        self::assertNotNull($confirmation);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('neither "jkt" nor "x5t#S256"');

        $confirmation->toClaim();
    }

    /** @return iterable<string, array{mixed, string}> */
    public static function malformedCnfProvider(): iterable
    {
        yield 'string' => [self::JKT, 'must be a JSON object'];
        yield 'null' => [null, 'must be a JSON object'];
        yield 'list' => [[self::JKT], 'must be a JSON object'];
        yield 'jkt not a string' => [['jkt' => ['value' => self::JKT]], 'member "jkt"'];
        yield 'jkt hex digest' => [['jkt' => hash('sha256', 'key')], 'member "jkt"'];
        yield 'x5t#S256 null' => [['x5t#S256' => null], 'member "x5t#S256"'];
        yield 'x5t#S256 padded' => [['x5t#S256' => self::X5T_S256 . '='], 'member "x5t#S256"'];
        yield 'x5t#S256 as printed in RFC 8705' => [['x5t#S256' => self::RFC8705_EXAMPLE], 'member "x5t#S256"'];
    }

    #[DataProvider('malformedCnfProvider')]
    public function testMalformedCnfIsRefused(mixed $cnf, string $message): void
    {
        $this->expectException(ClaimTypeException::class);
        $this->expectExceptionMessage($message);

        (new ClaimsSet(['cnf' => $cnf]))->confirmation();
    }
}
