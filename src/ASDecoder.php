<?php

declare(strict_types=1);

namespace AppleSignIn;

/**
 * Backward-compatible entry point for code written against v1/v2 of this
 * library. New code should use {@see AppleSignInDecoder} directly.
 *
 * @deprecated use AppleSignIn\AppleSignInDecoder
 */
class ASDecoder
{
    /**
     * Optional raw JSON payload of https://appleid.apple.com/auth/keys.
     * Populate it to avoid an HTTP request (cache hook); after decoding it
     * holds the keys fetched from Apple.
     */
    public static string $responseKeys = '';

    /**
     * @throws Exception\AppleSignInException
     */
    public static function getAppleSignInPayload(string $identityToken): ASPayload
    {
        $provider = self::$responseKeys !== ''
            ? new StaticPublicKeyProvider(self::$responseKeys)
            : new ApplePublicKeyProvider();

        $payload = new ASPayload((new AppleSignInDecoder($provider))->decode($identityToken));

        // Keep the legacy cache hook populated after a live fetch.
        if ($provider instanceof ApplePublicKeyProvider && $provider->getRawKeys() !== null) {
            self::$responseKeys = $provider->getRawKeys();
        }

        return $payload;
    }

    /**
     * @return array<string, \Firebase\JWT\Key>
     *
     * @throws Exception\AppleSignInException
     * @deprecated inject a PublicKeyProvider into AppleSignInDecoder instead.
     */
    public static function fetchPublicKey(): array
    {
        return (new ApplePublicKeyProvider())->getKeySet();
    }
}
