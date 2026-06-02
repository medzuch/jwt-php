<?php

declare(strict_types=1);

/**
 * php-fuzzer target — the JWE compact structural deserializer (no crypto).
 *
 * {@see CompactSerializer::deserialize()} parses an untrusted 5-segment
 * compact string into a {@see \Medzuch\Jwt\Jwe\ParsedJwe} or rejects it with a
 * {@see JwtException}. Anything else escaping is a bug.
 *
 * Run:
 *   tests/Fuzz/run.sh jwe_compact
 *
 * @var \PhpFuzzer\Config $config
 */

require __DIR__ . '/../../../vendor/autoload.php';

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwe\CompactSerializer;

$config->setAllowedExceptions([JwtException::class]);
$config->setMaxLen(8192);
$config->addDictionary(__DIR__ . '/../jose.dict');
$config->setTarget(static function (string $input): void {
    CompactSerializer::deserialize($input);
});
