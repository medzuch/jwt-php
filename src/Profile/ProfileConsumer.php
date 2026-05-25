<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\ParsedJwt;
use Medzuch\Jwt\Jwt\Validator;

/**
 * Shared consumer skeleton for the Layer 6 profiles.
 *
 * Every profile validates a compact JWT the same way: parse the structure,
 * run it through a pre-configured {@see Validator} (signature + registered
 * claims + `typ`), then apply the token-kind-specific semantic checks that
 * the generic validator cannot express. Subclasses supply the configured
 * validator and override {@see assertProfile()} for those extra rules.
 *
 * The two-phase split (structure, then crypto + claims) is the same one the
 * lower-level API exposes; the profile just bundles the common posture so
 * callers do not assemble it by hand.
 */
abstract class ProfileConsumer
{
    public function __construct(private readonly Validator $validator) {}

    /**
     * Parse and fully validate a compact JWT for this profile.
     *
     * @throws \Medzuch\Jwt\Exception\JwtException on any structural, crypto,
     *                                              or semantic failure
     */
    final public function parse(string $compact): ClaimsSet
    {
        $parsed = JwtParser::parse($compact);
        $claims = $this->validator->validate($parsed);
        $this->assertProfile($claims, $parsed);

        return $claims;
    }

    /**
     * Token-kind-specific checks beyond the generic validator. The default
     * is a no-op; profiles whose rules are fully expressed by required
     * claims and `typ` need not override it.
     */
    protected function assertProfile(ClaimsSet $claims, ParsedJwt $parsed): void {}
}
