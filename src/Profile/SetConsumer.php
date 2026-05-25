<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use Medzuch\Jwt\Exception\ClaimTypeException;
use Medzuch\Jwt\Exception\InvalidClaimException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\ParsedJwt;

/**
 * Consumer side of {@see SetProfile}. The wrapped validator enforces the
 * `secevent+jwt` type, the issuer, optional audience, and the RFC 8417
 * §2.2 required claims; this class adds the one rule the generic validator
 * cannot express — that `events` is a non-empty JSON object (a map of
 * event-type URIs to payloads), not an array or an empty object.
 *
 * @internal construct via {@see SetProfile::consumer()}
 */
final class SetConsumer extends ProfileConsumer
{
    protected function assertProfile(ClaimsSet $claims, ParsedJwt $parsed): void
    {
        $events = $claims->get('events');

        if (!is_array($events)) {
            throw new ClaimTypeException('SET "events" must be a JSON object of event-type URIs (RFC 8417 §2.2)');
        }
        // A populated JSON object decodes to an associative PHP array. Both
        // a JSON array (wrong shape) and an empty object `{}` decode to a
        // list (`[]` is a list) — reject either: a SET needs ≥1 event.
        if ($events === [] || array_is_list($events)) {
            throw new InvalidClaimException('SET "events" must be a non-empty JSON object of event-type URIs (RFC 8417 §2.2)');
        }
    }
}
