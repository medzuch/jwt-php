<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Profile;

use DateTimeInterface;
use LogicException;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jwt\JwtBuilder;
use stdClass;

/**
 * Fluent, immutable builder for an RFC 8417 Security Event Token. Returned
 * by {@see SetProfile::issue()} with the producer-side invariants applied;
 * the caller declares one or more events and any subject/audience.
 *
 * Events accumulate across {@see event()} calls and are serialised as the
 * `events` JSON object (§2.2) — event-type URI keys mapping to per-event
 * payload objects. There is intentionally no expiry setter (§4.1.4).
 *
 * @internal construct via {@see SetProfile::issue()}
 */
final class SetBuilder
{
    /**
     * @param array<string, array<string, mixed>|stdClass> $events
     */
    public function __construct(
        private readonly JwtBuilder $builder,
        private readonly array $events,
    ) {}

    public function subject(string $sub): self
    {
        return new self($this->builder->subject($sub), $this->events);
    }

    /** @param string|list<string> $aud */
    public function audience(string|array $aud): self
    {
        return new self($this->builder->audience($aud), $this->events);
    }

    public function notBefore(DateTimeInterface $when): self
    {
        return new self($this->builder->notBefore($when), $this->events);
    }

    public function issuedAt(DateTimeInterface $when): self
    {
        return new self($this->builder->issuedAt($when), $this->events);
    }

    public function jwtId(string $jti): self
    {
        return new self($this->builder->jwtId($jti), $this->events);
    }

    /**
     * Declare one security event. `$eventType` is the event identifier URI;
     * `$payload` is its event-specific object, which may be empty (an empty
     * payload serialises as `{}`, never `[]`, per §2.2). Calling twice with
     * the same type replaces the earlier payload.
     *
     * @param array<string, mixed> $payload
     */
    public function event(string $eventType, array $payload = []): self
    {
        if ($eventType === '') {
            throw new LogicException('SET event type must be a non-empty URI (RFC 8417 §2.2)');
        }
        $events = $this->events;
        $events[$eventType] = $payload === [] ? new stdClass() : $payload;

        return new self($this->builder->withClaim('events', $events), $events);
    }

    /**
     * Time of the event (`toe`, RFC 8417 §2.2), as a NumericDate.
     */
    public function timeOfEvent(DateTimeInterface $when): self
    {
        return new self($this->builder->withClaim('toe', $when->getTimestamp()), $this->events);
    }

    /**
     * Transaction identifier correlating the SET with other messages
     * (`txn`, RFC 8417 §2.2).
     */
    public function transactionId(string $txn): self
    {
        return new self($this->builder->withClaim('txn', $txn), $this->events);
    }

    public function withClaim(string $name, mixed $value): self
    {
        return new self($this->builder->withClaim($name, $value), $this->events);
    }

    public function withHeader(string $name, mixed $value): self
    {
        return new self($this->builder->withHeader($name, $value), $this->events);
    }

    public function build(): CompactJws
    {
        if ($this->events === []) {
            throw new LogicException('A SET must declare at least one event before build() (RFC 8417 §2.2)');
        }

        return $this->builder->build();
    }
}
