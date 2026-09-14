<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\CertificateThumbprint;
use Medzuch\Jwt\Key\Internal\Asn1;
use Medzuch\Jwt\Primitives\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The expected thumbprint comes from `openssl_x509_fingerprint()`, an
 * implementation independent of the one under test.
 */
#[CoversClass(CertificateThumbprint::class)]
#[UsesClass(Asn1::class)]
#[UsesClass(Base64Url::class)]
final class CertificateThumbprintTest extends TestCase
{
    private static string $pem;

    private static string $der;

    private static string $expected;

    public static function setUpBeforeClass(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($key);
        $csr = openssl_csr_new(['commonName' => 'client.example'], $key, ['digest_alg' => 'sha256']);
        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
        $certificate = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
        self::assertNotFalse($certificate);
        self::assertTrue(openssl_x509_export($certificate, $pem));
        self::assertIsString($pem);
        $fingerprint = openssl_x509_fingerprint($certificate, 'sha256', true);
        self::assertIsString($fingerprint);

        self::$pem = $pem;
        self::$der = (string) base64_decode(preg_replace('/-----[A-Z ]+-----|\s/', '', $pem) ?? '', true);
        self::$expected = Base64Url::encode($fingerprint);
    }

    public function testOfDerMatchesOpenSslFingerprint(): void
    {
        self::assertSame(self::$expected, CertificateThumbprint::ofDer(self::$der));
    }

    /** @return iterable<string, array{callable(string): string}> */
    public static function pemSpellingProvider(): iterable
    {
        yield 'as exported' => [static fn(string $pem): string => $pem];
        yield 'CRLF line breaks' => [static fn(string $pem): string => str_replace("\n", "\r\n", $pem)];
        yield 'no trailing newline, leading blank line' => [static fn(string $pem): string => "\n" . rtrim($pem)];
        yield 'line breaks folded into spaces' => [static fn(string $pem): string => str_replace("\n", ' ', $pem)];
        yield 'body on one line' => [static fn(string $pem): string => preg_replace('/(?<=[A-Za-z0-9+\/=])\n(?=[A-Za-z0-9+\/=])/', '', $pem) ?? ''];
        yield 'percent-encoded (nginx $ssl_client_escaped_cert)' => [static fn(string $pem): string => rawurlencode($pem)];
    }

    /** @param callable(string): string $spell */
    #[DataProvider('pemSpellingProvider')]
    public function testOfPemAcceptsWhatProxiesForward(callable $spell): void
    {
        self::assertSame(self::$expected, CertificateThumbprint::ofPem($spell(self::$pem)));
    }

    /** @return iterable<string, array{callable(string, string): string, string}> */
    public static function malformedPemProvider(): iterable
    {
        yield 'empty' => [static fn(): string => '', 'not a single PEM CERTIFICATE block'];
        yield 'DER instead of PEM' => [static fn(string $pem, string $der): string => $der, 'not a single PEM CERTIFICATE block'];
        yield 'bare base64 without armour' => [static fn(string $pem, string $der): string => base64_encode($der), 'not a single PEM CERTIFICATE block'];
        yield 'chain of two' => [static fn(string $pem): string => $pem . $pem, 'not a chain'];
        yield 'public key label' => [static fn(string $pem): string => str_replace('CERTIFICATE', 'PUBLIC KEY', $pem), 'not a single PEM CERTIFICATE block'];
        yield 'OpenSSL trusted certificate label' => [static fn(string $pem): string => str_replace('CERTIFICATE', 'TRUSTED CERTIFICATE', $pem), 'not a single PEM CERTIFICATE block'];
        yield 'text before armour' => [static fn(string $pem): string => "Subject: CN=client.example\n" . $pem, 'not a single PEM CERTIFICATE block'];
        yield 'form-encoded, + for space' => [static fn(string $pem): string => urlencode($pem), 'not a single PEM CERTIFICATE block'];
        yield 'percent-encoded twice' => [static fn(string $pem): string => rawurlencode(rawurlencode($pem)), 'not a single PEM CERTIFICATE block'];
        yield 'body base64 broken' => [static fn(): string => "-----BEGIN CERTIFICATE-----\nMII=A\n-----END CERTIFICATE-----\n", 'not valid base64'];
        yield 'body decodes to non-DER' => [static fn(): string => "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n", 'not a single DER structure'];
    }

    /** @param callable(string, string): string $spell */
    #[DataProvider('malformedPemProvider')]
    public function testOfPemRefusesMalformedInput(callable $spell, string $message): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage($message);

        CertificateThumbprint::ofPem($spell(self::$pem, self::$der));
    }

    /** @return iterable<string, array{callable(string, string): string, string}> */
    public static function malformedDerProvider(): iterable
    {
        yield 'empty' => [static fn(): string => '', 'ASN.1: unexpected end of input'];
        yield 'PEM instead of DER' => [static fn(string $pem): string => $pem, 'ASN.1: expected tag 0x30'];
        yield 'truncated' => [static fn(string $pem, string $der): string => substr($der, 0, -1), 'ASN.1: declared length exceeds buffer'];
        yield 'trailing byte' => [static fn(string $pem, string $der): string => $der . "\x00", 'Trailing bytes after DER SEQUENCE'];
        yield 'two certificates concatenated' => [static fn(string $pem, string $der): string => $der . $der, 'Trailing bytes after DER SEQUENCE'];
    }

    /** @param callable(string, string): string $spell */
    #[DataProvider('malformedDerProvider')]
    public function testOfDerRefusesAnythingButOneDerStructure(callable $spell, string $cause): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/^Certificate is not a single DER structure \(for PEM input use ofPem\(\)\): ' . preg_quote($cause, '/') . '/');

        CertificateThumbprint::ofDer($spell(self::$pem, self::$der));
    }
}
