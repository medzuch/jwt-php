<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Exception;

/**
 * `typ` header did not match the profile's required media type.
 *
 * Thrown wherever explicit typing is enforced (RFC 8725 §3.11): the profile
 * consumers pin their own media type (`at+jwt` for access tokens,
 * `secevent+jwt` for security event tokens), and
 * {@see \Medzuch\Jwt\Jwt\ValidatorBuilder::expectType()} pins one for
 * application-defined profiles.
 */
final class InvalidTypeException extends ClaimValidationException {}
