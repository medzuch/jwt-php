<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * A claim was present and structurally well-typed but violated a profile
 * rule that the generic {@see \Medzuch\Jwt\Jwt\Validator} does not encode.
 *
 * Used by the Layer 6 profiles for semantic checks that are specific to a
 * token kind — e.g. an OIDC ID token whose `azp` does not equal the
 * client, or whose `nonce` does not match the one bound to the request
 * (OpenID Connect Core 1.0 §3.1.3.7).
 */
final class InvalidClaimException extends ClaimValidationException {}
