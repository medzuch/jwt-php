<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Exception;

use Medzuch\Jwt\Exception\AlgorithmNotAllowedException;
use Medzuch\Jwt\Exception\ClaimTypeException;
use Medzuch\Jwt\Exception\ClaimValidationException;
use Medzuch\Jwt\Exception\ExpiredException;
use Medzuch\Jwt\Exception\InvalidAudienceException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\InvalidIssuerException;
use Medzuch\Jwt\Exception\InvalidSubjectException;
use Medzuch\Jwt\Exception\InvalidTypeException;
use Medzuch\Jwt\Exception\IssuedInFutureException;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Exception\KeyNotFoundException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Exception\MissingClaimException;
use Medzuch\Jwt\Exception\NotYetValidException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use RuntimeException;
use Throwable;

use function is_subclass_of;

/**
 * Structural assertions on the Exception hierarchy.
 *
 * One test file rather than one-per-class because the leaves carry no
 * behaviour — what matters is the inheritance shape. If a new leaf is
 * added without being wired into the providers below, the test makes
 * that obvious.
 */
#[CoversClass(MalformedJwtException::class)]
#[CoversClass(InvalidHeaderException::class)]
#[CoversClass(AlgorithmNotAllowedException::class)]
#[CoversClass(KeyNotFoundException::class)]
#[CoversClass(KeyMismatchException::class)]
#[CoversClass(SignatureVerificationException::class)]
#[CoversClass(ClaimValidationException::class)]
#[CoversClass(ExpiredException::class)]
#[CoversClass(NotYetValidException::class)]
#[CoversClass(IssuedInFutureException::class)]
#[CoversClass(InvalidIssuerException::class)]
#[CoversClass(InvalidAudienceException::class)]
#[CoversClass(InvalidSubjectException::class)]
#[CoversClass(InvalidTypeException::class)]
#[CoversClass(MissingClaimException::class)]
#[CoversClass(ClaimTypeException::class)]
final class ExceptionHierarchyTest extends TestCase
{
    /** @param class-string<Throwable> $class */
    #[DataProvider('leafExceptionProvider')]
    public function testLeafImplementsJwtException(string $class): void
    {
        self::assertTrue(
            is_subclass_of($class, JwtException::class),
            $class . ' must implement ' . JwtException::class,
        );
    }

    /** @param class-string<Throwable> $class */
    #[DataProvider('leafExceptionProvider')]
    public function testLeafIsRuntimeException(string $class): void
    {
        self::assertTrue(
            is_subclass_of($class, RuntimeException::class),
            $class . ' must extend RuntimeException',
        );
    }

    /** @param class-string $class */
    #[DataProvider('leafExceptionProvider')]
    public function testLeafIsFinal(string $class): void
    {
        $reflection = new ReflectionClass($class);

        self::assertTrue(
            $reflection->isFinal(),
            $class . ' must be final per docs/08-coding-standards.md',
        );
    }

    /** @param class-string<Throwable> $class */
    #[DataProvider('claimValidationLeafProvider')]
    public function testClaimLeafExtendsClaimValidationException(string $class): void
    {
        self::assertTrue(
            is_subclass_of($class, ClaimValidationException::class),
            $class . ' must extend ClaimValidationException',
        );
    }

    public function testClaimValidationExceptionIsAbstract(): void
    {
        $reflection = new ReflectionClass(ClaimValidationException::class);

        self::assertTrue($reflection->isAbstract());
    }

    public function testJwtExceptionIsAnInterface(): void
    {
        $reflection = new ReflectionClass(JwtException::class);

        self::assertTrue($reflection->isInterface());
    }

    public function testLeafCanBeInstantiatedAndCarriesMessage(): void
    {
        $e = new MalformedJwtException('boom');

        self::assertSame('boom', $e->getMessage());
    }

    public function testLeafCanWrapPreviousThrowable(): void
    {
        $cause = new RuntimeException('root cause');
        $e = new MalformedJwtException('outer', 0, $cause);

        self::assertSame($cause, $e->getPrevious());
    }

    /** @return iterable<string, array{class-string<Throwable>}> */
    public static function leafExceptionProvider(): iterable
    {
        yield 'MalformedJwt' => [MalformedJwtException::class];
        yield 'InvalidHeader' => [InvalidHeaderException::class];
        yield 'AlgorithmNotAllowed' => [AlgorithmNotAllowedException::class];
        yield 'KeyNotFound' => [KeyNotFoundException::class];
        yield 'KeyMismatch' => [KeyMismatchException::class];
        yield 'SignatureVerification' => [SignatureVerificationException::class];
        yield 'Expired' => [ExpiredException::class];
        yield 'NotYetValid' => [NotYetValidException::class];
        yield 'IssuedInFuture' => [IssuedInFutureException::class];
        yield 'InvalidIssuer' => [InvalidIssuerException::class];
        yield 'InvalidAudience' => [InvalidAudienceException::class];
        yield 'InvalidSubject' => [InvalidSubjectException::class];
        yield 'InvalidType' => [InvalidTypeException::class];
        yield 'MissingClaim' => [MissingClaimException::class];
        yield 'ClaimType' => [ClaimTypeException::class];
    }

    /** @return iterable<string, array{class-string<Throwable>}> */
    public static function claimValidationLeafProvider(): iterable
    {
        yield 'Expired' => [ExpiredException::class];
        yield 'NotYetValid' => [NotYetValidException::class];
        yield 'IssuedInFuture' => [IssuedInFutureException::class];
        yield 'InvalidIssuer' => [InvalidIssuerException::class];
        yield 'InvalidAudience' => [InvalidAudienceException::class];
        yield 'InvalidSubject' => [InvalidSubjectException::class];
        yield 'InvalidType' => [InvalidTypeException::class];
        yield 'MissingClaim' => [MissingClaimException::class];
        yield 'ClaimType' => [ClaimTypeException::class];
    }
}
