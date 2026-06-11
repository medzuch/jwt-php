<?php

declare(strict_types=1);

/**
 * php-fuzzer target — base64url decoding (the first thing applied to every
 * compact-JWS/JWT segment).
 *
 * {@see Base64Url::decode()} must return the decoded bytes or throw a
 * {@see JwtException} ({@see \Medzuch\Jwt\Exception\MalformedJwtException});
 * a raw `SodiumException`, `ValueError`, or `Error` escaping is a bug.
 *
 * Run:
 *   tests/Fuzz/run.sh base64url_decode
 *
 * @var \PhpFuzzer\Config $config
 */

require __DIR__ . '/../../../vendor/autoload.php';

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Primitives\Base64Url;

$config->setAllowedExceptions([JwtException::class]);
$config->setMaxLen(1024);
$config->setTarget(static function (string $input): void {
    Base64Url::decode($input);
});
