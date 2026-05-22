<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\Unsecured;

use LogicException;
use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Unsecured\None;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\Key;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(None::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(Key::class)]
final class NoneTest extends TestCase
{
    public function testIdentity(): void
    {
        $algo = new None();

        self::assertSame('none', $algo->name());
        self::assertSame(AlgorithmFamily::None, $algo->family());
    }

    public function testSignAlwaysThrows(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/UnsecuredJwtBuilder/');

        (new None())->sign('input', $key);
    }

    public function testVerifyReturnsTrueOnEmptySignature(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        self::assertTrue((new None())->verify('input', '', $key));
    }

    public function testVerifyReturnsFalseOnAnySignatureBytes(): void
    {
        $key = HmacKey::fromBinary(random_bytes(32), 'HS256');

        self::assertFalse((new None())->verify('input', "\x00", $key));
        self::assertFalse((new None())->verify('input', 'anything', $key));
    }
}
