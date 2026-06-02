<?php

declare(strict_types=1);

/**
 * php-fuzzer target — the JWT compact parser.
 *
 * Contract under test: {@see JwtParser::parse()} must reject *any* untrusted
 * input with a {@see JwtException} and nothing else. An `Error`, `TypeError`,
 * `ValueError`, `JsonException`, or a raw SPL exception leaking out is a bug
 * (P0 per docs/07-testing-strategy.md) — `setAllowedExceptions()` encodes that
 * contract, so the fuzzer records anything outside the JwtException family as
 * a crash.
 *
 * Run:
 *   tests/Fuzz/run.sh jwt_parser
 *
 * @var \PhpFuzzer\Config $config
 */

require __DIR__ . '/../../../vendor/autoload.php';

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\JwtParser;

$config->setAllowedExceptions([JwtException::class]);
$config->setMaxLen(4096);
$config->addDictionary(__DIR__ . '/../jose.dict');
$config->setTarget(static function (string $input): void {
    JwtParser::parse($input);
});
