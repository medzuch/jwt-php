<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Conformance;

use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Unsecured\None;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\Unsecured\UnsecuredJwtBuilder;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Phase 1 exit criterion: an alg:none token is rejected through every
 * safe-path entry. The library can produce such tokens (via the
 * deliberately-namespaced UnsecuredJwtBuilder) for legacy interop, but
 * it cannot consume them — even when the validator's algorithm allowlist
 * explicitly includes None.
 */
#[CoversNothing]
final class AlgNoneRejectionTest extends TestCase
{
    public function testJwtParserRefusesAlgNoneToken(): void
    {
        $jwt = UnsecuredJwtBuilder::create()->subject('user-1')->build();

        $this->expectException(MalformedJwtException::class);
        $this->expectExceptionMessageMatches('/signature segment is empty/');

        JwtParser::parse($jwt->value);
    }

    public function testValidatorWithNoneInAllowlistStillCannotParse(): void
    {
        // Even if the caller opts into the None algorithm, the parser
        // refuses the empty-signature compact form before the validator
        // ever sees it. None is effectively unreachable from the safe
        // consume path.
        $jwt = UnsecuredJwtBuilder::create()->subject('user-1')->build();

        $validator = ValidatorBuilder::create()
            ->expectAlgorithms([new Hs256(), new None()])
            ->withKeys(JwkSet::of(HmacKey::fromBinary(random_bytes(32), 'HS256')))
            ->build();

        $this->expectException(MalformedJwtException::class);

        $validator->validate(JwtParser::parse($jwt->value));
    }
}
