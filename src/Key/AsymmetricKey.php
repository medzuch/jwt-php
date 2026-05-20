<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Key;

/**
 * Asymmetric keys come as a Public/Private pair; one half cannot do
 * what the other can.
 *
 * The concrete subclasses (RsaPublicKey/RsaPrivateKey in Phase 1;
 * EcKey + OkpKey in Phase 2) implement the {@see PublicKey} or
 * {@see PrivateKey} marker accordingly.
 */
abstract class AsymmetricKey extends Key
{
}
