<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

/**
 * Consumer side of {@see AccessTokenProfile}. The validator it wraps is
 * configured (in {@see AccessTokenProfile::consumer()}) to enforce the
 * `at+jwt` type, the issuer, the audience, and the RFC 9068 §2.2 required
 * claim set, so no profile-specific post-check is needed here — presence
 * of `client_id` and the rest is covered by the validator's required-claim
 * gate.
 *
 * @internal construct via {@see AccessTokenProfile::consumer()}
 */
final class AccessTokenConsumer extends ProfileConsumer {}
