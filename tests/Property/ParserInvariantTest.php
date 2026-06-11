<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Property;

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\Jwt\Tests\Support\HostileInputGenerator;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Property-based robustness tests for every parser that touches untrusted
 * input. The invariant, identical to the fuzzing contract
 * (tests/Fuzz/README.md), is:
 *
 *   > A parser fed arbitrary bytes must reject them with a {@see JwtException}
 *   > and nothing else.
 *
 * Any other `Throwable` escaping — an `Error`, `TypeError`, `ValueError`,
 * `JsonException`, `SodiumException`, or a raw SPL exception — is a bug.
 *
 * Inputs come from a {@see HostileInputGenerator} seeded deterministically, so
 * this runs on every `make test` (unlike the wall-clock-bounded nightly
 * fuzzer) and any failure replays from the seed *and* carries the offending
 * bytes (base64) in the message for immediate reproduction.
 *
 * Override the seed with `JWT_PROPERTY_SEED` to widen the explored space in CI;
 * the default is fixed for reproducible local runs.
 */
#[CoversNothing]
final class ParserInvariantTest extends TestCase
{
    private const ITERATIONS = 2000;

    /**
     * The parser entry points under test, keyed by name. Each is a single
     * `string -> void` call mirroring a tests/Fuzz target.
     *
     * @return iterable<string, array{callable(string): mixed}>
     */
    public static function parsers(): iterable
    {
        yield 'jwt_parser' => [static fn(string $s) => JwtParser::parse($s)];
        yield 'json_decode' => [static fn(string $s) => Json::decode($s)];
        yield 'base64url_decode' => [static fn(string $s) => Base64Url::decode($s)];
        yield 'jws_compact' => [static fn(string $s) => \Medzuch\Jwt\Jws\CompactSerializer::deserialize($s)];
        yield 'jwe_compact' => [static fn(string $s) => \Medzuch\Jwt\Jwe\CompactSerializer::deserialize($s)];
        yield 'jws_json' => [static fn(string $s) => \Medzuch\Jwt\Jws\JsonSerializer::deserialize($s)];
        yield 'jwe_json' => [static fn(string $s) => \Medzuch\Jwt\Jwe\JsonSerializer::deserialize($s)];
    }

    /**
     * @param callable(string): mixed $parse
     */
    #[DataProvider('parsers')]
    public function testOnlyJwtExceptionEscapes(callable $parse): void
    {
        $env = getenv('JWT_PROPERTY_SEED');
        $baseSeed = (int) ($env !== false && $env !== '' ? $env : '20260603');
        $generator = new HostileInputGenerator();
        $generator->seed($baseSeed);

        for ($i = 0; $i < self::ITERATIONS; ++$i) {
            $input = $generator->next();

            try {
                $parse($input);
            } catch (JwtException) {
                // Contract upheld: the library rejected hostile input cleanly.
            } catch (Throwable $e) {
                self::fail(sprintf(
                    "Parser leaked a non-JwtException on hostile input.\n"
                    . "  seed:      %d\n"
                    . "  iteration: %d\n"
                    . "  exception: %s: %s\n"
                    . "  thrown at: %s:%d\n"
                    . "  input b64: %s",
                    $baseSeed,
                    $i,
                    $e::class,
                    $e->getMessage(),
                    $e->getFile(),
                    $e->getLine(),
                    base64_encode($input),
                ));
            }

            // The verified property: this input upheld the contract (returned
            // or threw a JwtException). Count it so the test is never flagged
            // as risky, without a tautological end-of-loop assertion.
            $this->addToAssertionCount(1);
        }
    }
}
