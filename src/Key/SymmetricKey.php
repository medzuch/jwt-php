<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

/**
 * Symmetric keys (a single secret used for both sign and verify).
 *
 * Implements both {@see PublicKey} and {@see PrivateKey} markers so that
 * symmetric algorithms can declare one parameter type that accepts the
 * one secret regardless of the operation.
 */
abstract class SymmetricKey extends Key implements PublicKey, PrivateKey {}
