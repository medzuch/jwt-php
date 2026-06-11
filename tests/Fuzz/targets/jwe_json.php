<?php

declare(strict_types=1);

/**
 * php-fuzzer target — the JWE JSON Serialization deserializer (no crypto).
 *
 * {@see JsonSerializer::deserialize()} parses an untrusted flattened/general
 * JSON JWE into a {@see \Medzuch\Jwt\Jwe\ParsedJwe} or rejects it with a
 * {@see JwtException}. Anything else escaping is a bug.
 *
 * Run:
 *   tests/Fuzz/run.sh jwe_json
 *
 * @var \PhpFuzzer\Config $config
 */

require __DIR__ . '/../../../vendor/autoload.php';

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwe\JsonSerializer;

$config->setAllowedExceptions([JwtException::class]);
$config->setMaxLen(8192);
$config->addDictionary(__DIR__ . '/../jose.dict');
$config->setTarget(static function (string $input): void {
    JsonSerializer::deserialize($input);
});
