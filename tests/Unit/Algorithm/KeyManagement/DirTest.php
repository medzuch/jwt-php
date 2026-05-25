<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Algorithm\KeyManagement;

use Medzuch\Jwt\Algorithm\AlgorithmFamily;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\Dir;
use Medzuch\Jwt\Algorithm\KeyManagementMode;
use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\OctKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Dir::class)]
#[UsesClass(AlgorithmFamily::class)]
#[UsesClass(KeyManagementMode::class)]
#[UsesClass(\Medzuch\Jwt\Algorithm\CekEncryptionResult::class)]
#[UsesClass(A256Gcm::class)]
#[UsesClass(OctKey::class)]
#[UsesClass(HmacKey::class)]
#[UsesClass(\Medzuch\Jwt\Key\Key::class)]
#[UsesClass(\Medzuch\Jwt\Key\SymmetricKey::class)]
final class DirTest extends TestCase
{
    public function testMetadata(): void
    {
        $dir = new Dir();

        self::assertSame('dir', $dir->name());
        self::assertSame(AlgorithmFamily::Direct, $dir->family());
        self::assertSame(KeyManagementMode::DirectEncryption, $dir->mode());
    }

    public function testEncryptKeyUsesSharedKeyAsCekWithNoEncryptedKey(): void
    {
        $bytes = random_bytes(32);
        $key = OctKey::fromBinary($bytes, 'A256GCM');

        $result = (new Dir())->encryptKey($key, new A256Gcm());

        self::assertSame($bytes, $result->cek);
        self::assertSame('', $result->encryptedKey);
        self::assertSame([], $result->headerParameters);
    }

    public function testDecryptKeyRecoversSharedKey(): void
    {
        $bytes = random_bytes(32);
        $key = OctKey::fromBinary($bytes, 'A256GCM');

        self::assertSame($bytes, (new Dir())->decryptKey($key, new A256Gcm(), '', ['alg' => 'dir', 'enc' => 'A256GCM']));
    }

    public function testRejectsNonOctKey(): void
    {
        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/requires an OctKey/');

        (new Dir())->encryptKey(HmacKey::fromBinary(random_bytes(32), 'HS256'), new A256Gcm());
    }

    public function testRejectsKeyBoundToDifferentContentAlgorithm(): void
    {
        // The shared key is bound to A128GCM but the JWE uses A256GCM.
        $key = OctKey::fromBinary(random_bytes(16), 'A128GCM');

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/A128GCM.*A256GCM|cannot be used/');

        (new Dir())->encryptKey($key, new A256Gcm());
    }

    public function testDecryptRejectsNonEmptyEncryptedKey(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM');

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessageMatches('/must not carry a JWE Encrypted Key/');

        (new Dir())->decryptKey($key, new A256Gcm(), 'unexpected', ['alg' => 'dir', 'enc' => 'A256GCM']);
    }

    public function testEnforcesKeyOpsOnEncrypt(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', keyOps: ['decrypt']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/does not permit operation "encrypt"/');

        (new Dir())->encryptKey($key, new A256Gcm());
    }

    public function testEnforcesKeyOpsOnDecrypt(): void
    {
        $key = OctKey::fromBinary(random_bytes(32), 'A256GCM', keyOps: ['encrypt']);

        $this->expectException(KeyMismatchException::class);
        $this->expectExceptionMessageMatches('/does not permit operation "decrypt"/');

        (new Dir())->decryptKey($key, new A256Gcm(), '', ['alg' => 'dir', 'enc' => 'A256GCM']);
    }
}
