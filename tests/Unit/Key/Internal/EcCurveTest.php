<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key\Internal;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\Internal\EcCurve;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(EcCurve::class)]
final class EcCurveTest extends TestCase
{
    /**
     * @param non-empty-string $jwkName
     * @param non-empty-string $opensslName
     * @param non-empty-string $alg
     * @param non-empty-string $oid
     */
    #[DataProvider('blessedCurves')]
    public function testFromJwkNameProducesExpectedMetadata(string $jwkName, string $opensslName, string $alg, string $oid, int $coordSize): void
    {
        $curve = EcCurve::fromJwkName($jwkName);

        self::assertSame($jwkName, $curve->jwkName);
        self::assertSame($opensslName, $curve->opensslName);
        self::assertSame($oid, $curve->oid);
        self::assertSame($coordSize, $curve->coordSize);
        self::assertSame($alg, $curve->alg);
    }

    /**
     * @param non-empty-string $jwkName
     * @param non-empty-string $opensslName
     * @param non-empty-string $alg
     */
    #[DataProvider('blessedCurves')]
    public function testFromOpensslNameMatchesJwkName(string $jwkName, string $opensslName, string $alg, string $oid, int $coordSize): void
    {
        self::assertSame($jwkName, EcCurve::fromOpensslName($opensslName)->jwkName);
    }

    /**
     * @param non-empty-string $jwkName
     * @param non-empty-string $opensslName
     * @param non-empty-string $alg
     */
    #[DataProvider('blessedCurves')]
    public function testFromAlgMatchesJwkName(string $jwkName, string $opensslName, string $alg, string $oid, int $coordSize): void
    {
        self::assertSame($jwkName, EcCurve::fromAlg($alg)->jwkName);
    }

    /** @return iterable<string, array{non-empty-string, non-empty-string, non-empty-string, non-empty-string, positive-int}> */
    public static function blessedCurves(): iterable
    {
        yield 'P-256' => ['P-256', 'prime256v1', 'ES256', '1.2.840.10045.3.1.7', 32];
        yield 'P-384' => ['P-384', 'secp384r1', 'ES384', '1.3.132.0.34', 48];
        yield 'P-521' => ['P-521', 'secp521r1', 'ES512', '1.3.132.0.35', 66];
    }

    public function testFromJwkNameRejectsUnsupportedCurve(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Unsupported EC curve "secp256k1"');

        EcCurve::fromJwkName('secp256k1');
    }

    public function testFromOpensslNameRejectsUnsupportedCurve(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Unsupported OpenSSL EC curve "brainpoolP256r1"');

        EcCurve::fromOpensslName('brainpoolP256r1');
    }

    public function testFromAlgRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Unsupported ECDSA algorithm "ES256K"');

        EcCurve::fromAlg('ES256K');
    }
}
