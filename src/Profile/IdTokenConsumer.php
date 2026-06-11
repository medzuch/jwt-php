<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Exception\InvalidClaimException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\ParsedJwt;
use Medzuch\Jwt\Jwt\Validator;
use Psr\Log\LoggerInterface;

/**
 * Consumer side of {@see IdTokenProfile}. On top of the validator's
 * signature / issuer / audience / required-claim checks, it applies the
 * ID-token-specific rules from OpenID Connect Core 1.0 §3.1.3.7:
 *
 *  - When the token's audience is plural, `azp` MUST be present.
 *  - When `azp` is present, it MUST equal the client.
 *  - When a `nonce` was bound to the authentication request, the token's
 *    `nonce` MUST match it.
 *
 * Obtain via {@see IdTokenProfile::consumer()} rather than constructing directly.
 */
final class IdTokenConsumer extends ProfileConsumer
{
    /** @internal Construct via {@see IdTokenProfile::consumer()}; the constructor signature is not part of the frozen public API. */
    public function __construct(
        Validator $validator,
        private readonly string $clientId,
        private readonly ?string $expectedNonce,
        ?LoggerInterface $logger = null,
        ?LogLevels $logLevels = null,
    ) {
        parent::__construct($validator, 'id-token', $logger, $logLevels);
    }

    protected function assertProfile(ClaimsSet $claims, ParsedJwt $parsed): void
    {
        $azp = $claims->getString('azp');

        if (count($claims->audience()) > 1 && $azp === null) {
            throw new InvalidClaimException('ID token has multiple audiences but no "azp" claim (OIDC Core §3.1.3.7)');
        }

        if ($azp !== null && $azp !== $this->clientId) {
            throw new InvalidClaimException(sprintf('ID token "azp" is "%s", expected the client "%s" (OIDC Core §3.1.3.7)', $azp, $this->clientId));
        }

        if ($this->expectedNonce !== null && $claims->getString('nonce') !== $this->expectedNonce) {
            throw new InvalidClaimException('ID token "nonce" does not match the value bound to the authentication request (OIDC Core §3.1.3.7)');
        }
    }
}
