<?php

declare(strict_types=1);

namespace AppleSignIn;

use Firebase\JWT\Key;

/**
 * Provides the Apple public keys used to verify identity token signatures,
 * keyed by the JWT "kid" header.
 */
interface PublicKeyProvider
{
    /**
     * @return array<string, Key>
     */
    public function getKeySet(): array;
}
