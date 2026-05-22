<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Jwt;

use Medzuch\Jwt\Jws\ParsedJws;

/**
 * Phase-1 result of {@see JwtParser::parse()}: the JWT is structurally
 * sound but its signature has NOT been verified and its claims have NOT
 * been validated. Hand this to {@see Validator::validate()} to advance.
 */
final readonly class ParsedJwt
{
    public function __construct(
        public Header $header,
        public ClaimsSet $unverifiedClaims,
        public ParsedJws $jws,
    ) {}
}
