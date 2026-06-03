<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Diagnostics\SecurityLog;
use Medzuch\Jwt\Exception\ClaimValidationException;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\ParsedJwt;
use Medzuch\Jwt\Jwt\Validator;
use Psr\Log\LoggerInterface;

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
 *
 * **Logging.** When a PSR-3 logger is attached (via the profile's
 * `consumer()` factory) the consumer is the single logging owner for the
 * whole parse: the {@see Validator} it wraps is built without a logger, so
 * each outcome — structural/crypto failure, claim rejection (including the
 * profile-specific rules below), or acceptance — is logged exactly once, with
 * the profile name in the redacted context.
 */
abstract class ProfileConsumer
{
    private readonly ?SecurityLog $log;

    public function __construct(
        private readonly Validator $validator,
        private readonly string $profileName,
        ?LoggerInterface $logger = null,
        ?LogLevels $logLevels = null,
    ) {
        $this->log = $logger === null ? null : SecurityLog::for($logger, $logLevels);
    }

    /**
     * Parse and fully validate a compact JWT for this profile.
     *
     * @throws \Medzuch\Jwt\Exception\JwtException on any structural, crypto,
     *                                              or semantic failure
     */
    final public function parse(string $compact): ClaimsSet
    {
        try {
            $parsed = JwtParser::parse($compact);
        } catch (JwtException $e) {
            // Structural failure: no usable header yet, so no kid/alg.
            $this->log?->verificationFailed($e, null, null, $this->profileName);

            throw $e;
        }

        $kid = $parsed->header->keyId();
        $alg = $parsed->header->algorithm();

        try {
            $claims = $this->validator->validate($parsed);
            $this->assertProfile($claims, $parsed);
        } catch (ClaimValidationException $e) {
            // A signed, structurally valid token whose claims (generic or
            // profile-specific) did not satisfy the policy.
            $this->log?->claimRejected($e, $kid, $alg, $this->profileName);

            throw $e;
        } catch (JwtException $e) {
            // Signature / algorithm / key failure from the validator.
            $this->log?->verificationFailed($e, $kid, $alg, $this->profileName);

            throw $e;
        }

        $this->log?->tokenAccepted($kid, $alg, $parsed->header->type(), $this->profileName);

        return $claims;
    }

    /**
     * Token-kind-specific checks beyond the generic validator. The default
     * is a no-op; profiles whose rules are fully expressed by required
     * claims and `typ` need not override it.
     */
    protected function assertProfile(ClaimsSet $claims, ParsedJwt $parsed): void {}
}
