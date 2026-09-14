<?php

declare(strict_types=1);

namespace AppleSignIn;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;

/**
 * Key provider backed by an in-memory key set. Accepts either a key set as
 * returned by {@see JWK::parseKeySet()} or a raw Apple JWKS payload
 * (array or JSON string fetched from https://appleid.apple.com/auth/keys).
 */
final class StaticPublicKeyProvider implements PublicKeyProvider
{
    /** @var array<string, Key>|null */
    private ?array $keySet = null;

    /** @var array<string, Key>|array{keys: array<int, array<string, string>>}|string */
    private array|string $jwks;

    /**
     * @param array<string, Key>|array{keys: array<int, array<string, string>>}|string $jwks
     */
    public function __construct(array|string $jwks)
    {
        $this->jwks = $jwks;
    }

    public function getKeySet(): array
    {
        if ($this->keySet === null) {
            $jwks = $this->jwks;

            if (is_string($jwks)) {
                $jwks = json_decode($jwks, true, 512, JSON_THROW_ON_ERROR);
            }

            $this->keySet = is_array(current($jwks)) && isset($jwks['keys'])
                ? JWK::parseKeySet($jwks, AppleSignInDecoder::ALGORITHM)
                : $jwks;
        }

        return $this->keySet;
    }
}
