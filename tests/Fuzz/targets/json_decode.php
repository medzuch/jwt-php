<?php

declare(strict_types=1);

/**
 * php-fuzzer target — the strict JSON decoder (UTF-8 + duplicate-key rejection).
 *
 * {@see Json::decode()} must turn arbitrary bytes into either a decoded array
 * or a {@see JwtException} ({@see \Medzuch\Jwt\Exception\MalformedJwtException}).
 * A raw `JsonException`, `ValueError`, or `Error` escaping is a bug.
 *
 * Run:
 *   tests/Fuzz/run.sh json_decode
 *
 * @var \PhpFuzzer\Config $config
 */

require __DIR__ . '/../../../vendor/autoload.php';

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Primitives\Json;

$config->setAllowedExceptions([JwtException::class]);
$config->setMaxLen(4096);
$config->addDictionary(__DIR__ . '/../jose.dict');
$config->setTarget(static function (string $input): void {
    Json::decode($input);
});
