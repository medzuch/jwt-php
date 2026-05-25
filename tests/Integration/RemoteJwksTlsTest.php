<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Integration;

use Medzuch\Jwt\Exception\JwksResolutionException;
use Medzuch\Jwt\Key\Resolver\RemoteJwksResolver;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Tests\Support\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\Psr18Client;

/**
 * Exit-criterion test for Phase 2: {@see RemoteJwksResolver} fetching a
 * JWKS over real TLS, against a locally spun HTTPS server presenting a
 * self-signed certificate.
 *
 * Proves two things end-to-end with a genuine PSR-18 client (Symfony's,
 * curl- or stream-backed):
 *   1. With the CA trusted, the document is fetched over TLS and the key
 *      resolves.
 *   2. With the CA *not* trusted, the handshake is rejected — confirming
 *      TLS peer verification is active, not silently disabled. The
 *      transport failure surfaces as a {@see JwksResolutionException}.
 *
 * The server runs in a child PHP process (PHP's built-in server has no
 * TLS), serving the JWKS on a loopback port over `stream_socket_server`.
 */
#[CoversNothing]
final class RemoteJwksTlsTest extends TestCase
{
    private const KID = 'bilbo.baggins@hobbiton.example';

    private string $dir;
    private string $certPath;
    /** @var resource|null */
    private $proc;
    /** @var array<int, resource> */
    private array $pipes = [];
    private string $url;

    protected function setUp(): void
    {
        if (!\function_exists('proc_open')) {
            self::markTestSkipped('proc_open is disabled');
        }

        $this->dir = sys_get_temp_dir() . '/jwks-tls-' . bin2hex(random_bytes(6));
        if (!mkdir($this->dir) && !is_dir($this->dir)) {
            self::markTestSkipped('could not create temp dir');
        }

        $this->certPath = $this->dir . '/cert.pem';
        $keyPath = $this->dir . '/key.pem';
        $this->generateSelfSignedCert($this->certPath, $keyPath);

        $jwksPath = $this->dir . '/jwks.json';
        file_put_contents($jwksPath, $this->jwksDocument());

        $this->url = 'https://127.0.0.1:' . $this->startServer($this->certPath, $keyPath, $jwksPath) . '/jwks.json';
    }

    protected function tearDown(): void
    {
        if (\is_resource($this->proc)) {
            proc_terminate($this->proc, 9);
            foreach ($this->pipes as $pipe) {
                if (\is_resource($pipe)) {
                    fclose($pipe);
                }
            }
            proc_close($this->proc);
        }
        if (isset($this->dir) && is_dir($this->dir)) {
            $files = glob($this->dir . '/*');
            if ($files !== false) {
                array_map('unlink', $files);
            }
            rmdir($this->dir);
        }
    }

    public function testResolvesOverTlsWhenCertificateAuthorityIsTrusted(): void
    {
        $resolver = new RemoteJwksResolver(
            $this->url,
            $this->psr18Client($this->certPath),
            new Psr17Factory(),
            new InMemoryCache(),
            FrozenClock::at('2026-05-21T00:00:00+00:00'),
        );

        $key = $resolver->resolve(['kid' => self::KID, 'alg' => 'ES512']);

        self::assertSame(self::KID, $key->kid());
        self::assertSame('ES512', $key->alg());
    }

    public function testRejectsServerWhoseCertificateIsNotTrusted(): void
    {
        // No cafile: the self-signed cert is not in the default trust store,
        // so a verifying client must refuse the handshake.
        $resolver = new RemoteJwksResolver(
            $this->url,
            $this->psr18Client(null),
            new Psr17Factory(),
            new InMemoryCache(),
            FrozenClock::at('2026-05-21T00:00:00+00:00'),
        );

        $this->expectException(JwksResolutionException::class);

        $resolver->resolve(['kid' => self::KID, 'alg' => 'ES512']);
    }

    private function psr18Client(?string $cafile): Psr18Client
    {
        $options = ['timeout' => 5, 'max_duration' => 10, 'verify_peer' => true, 'verify_host' => true];
        if ($cafile !== null) {
            $options['cafile'] = $cafile;
        }
        $factory = new Psr17Factory();

        return new Psr18Client(HttpClient::create($options), $factory, $factory);
    }

    private function generateSelfSignedCert(string $certPath, string $keyPath): void
    {
        $cmd = sprintf(
            'openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 1 -nodes -subj %s -addext %s 2>&1',
            escapeshellarg($keyPath),
            escapeshellarg($certPath),
            escapeshellarg('/CN=127.0.0.1'),
            escapeshellarg('subjectAltName=IP:127.0.0.1'),
        );
        exec($cmd, $output, $status);
        if ($status !== 0 || !is_file($certPath)) {
            self::markTestSkipped('openssl could not generate a test certificate: ' . implode("\n", $output));
        }
    }

    private function startServer(string $cert, string $key, string $jwks): string
    {
        $script = $this->dir . '/server.php';
        file_put_contents($script, $this->serverSource());

        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $proc = proc_open(['php', $script, $cert, $key, $jwks], $descriptors, $pipes);
        if (!\is_resource($proc)) {
            self::markTestSkipped('could not start the TLS test server');
        }
        $this->proc = $proc;
        $this->pipes = $pipes;
        stream_set_blocking($pipes[1], false);

        $port = '';
        $deadline = microtime(true) + 10.0;
        while (microtime(true) < $deadline) {
            $line = fgets($pipes[1]);
            if (is_string($line) && trim($line) !== '') {
                $port = trim($line);

                break;
            }
            usleep(50_000);
        }

        if (!ctype_digit($port)) {
            self::markTestSkipped('TLS test server did not report a port: ' . stream_get_contents($pipes[2]));
        }

        return $port;
    }

    private function serverSource(): string
    {
        return <<<'PHP'
            <?php
            [, $cert, $key, $jwks] = $argv;
            $ctx = stream_context_create(['ssl' => [
                'local_cert' => $cert,
                'local_pk' => $key,
                'allow_self_signed' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
            ]]);
            $server = @stream_socket_server('tls://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
            if ($server === false) {
                fwrite(STDERR, "bind failed: $errstr");
                exit(1);
            }
            $name = stream_socket_get_name($server, false);
            echo substr($name, strrpos($name, ':') + 1) . "\n";
            $body = (string) file_get_contents($jwks);
            $response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body;
            while (true) {
                $conn = @stream_socket_accept($server, 30);
                if ($conn === false) {
                    continue;
                }
                @fread($conn, 16384);
                @fwrite($conn, $response);
                @fclose($conn);
            }
            PHP;
    }

    private function jwksDocument(): string
    {
        // The RFC 7520 §3.2 P-521 public key, published as a one-key JWKS.
        return json_encode([
            'keys' => [
                [
                    'kty' => 'EC',
                    'alg' => 'ES512',
                    'kid' => self::KID,
                    'crv' => 'P-521',
                    'x' => 'AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt',
                    'y' => 'AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1',
                ],
            ],
        ], JSON_THROW_ON_ERROR);
    }
}
