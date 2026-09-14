<?php

declare(strict_types=1);

namespace AppleSignIn;

use AppleSignIn\Exception\AppleSignInException;
use Firebase\JWT\JWT;

/**
 * Builds the ES256 client_secret JWT required by the Sign In with Apple
 * server-to-server endpoints (token, revoke, ...).
 *
 * @see https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
 */
final class ClientSecretGenerator
{
    public const AUDIENCE = 'https://appleid.apple.com';

    /**
     * Apple rejects client secrets longer than 6 months (15777000 seconds).
     */
    public const MAX_TTL = 15777000;
    public const DEFAULT_TTL = 15552000; // 180 days

    /**
     * @param string   $teamId     10-character Apple Developer Team ID
     * @param string   $clientId   App bundle ID or Services ID
     * @param string   $keyId      Key ID of the .p8 Sign In with Apple key
     * @param string   $privateKey PEM contents of the .p8 key, raw key body, or its path
     * @param int      $ttlSeconds Token lifetime, max 6 months
     * @param int|null $issuedAt   Issued-at unix timestamp (defaults to now)
     *
     * @throws AppleSignInException
     */
    public static function generate(
        string $teamId,
        string $clientId,
        string $keyId,
        string $privateKey,
        int $ttlSeconds = self::DEFAULT_TTL,
        ?int $issuedAt = null,
    ): string {
        if ($ttlSeconds <= 0 || $ttlSeconds > self::MAX_TTL) {
            throw new AppleSignInException(sprintf(
                'client_secret TTL must be between 1 and %d seconds.',
                self::MAX_TTL,
            ));
        }

        $pem = self::loadPrivateKey($privateKey);
        $issuedAt ??= time();

        return JWT::encode(
            [
                'iss' => $teamId,
                'iat' => $issuedAt,
                'exp' => $issuedAt + $ttlSeconds,
                'aud' => self::AUDIENCE,
                'sub' => $clientId,
            ],
            $pem,
            'ES256',
            $keyId,
        );
    }

    /**
     * @throws AppleSignInException
     */
    private static function loadPrivateKey(string $privateKey): string
    {
        if ($privateKey === '') {
            throw new AppleSignInException('A Sign In with Apple private key is required.');
        }

        if (str_starts_with($privateKey, '-----BEGIN PRIVATE KEY-----')) {
            return $privateKey;
        }

        if (is_file($privateKey)) {
            $contents = file_get_contents($privateKey);
            if ($contents === false) {
                throw new AppleSignInException(sprintf('Unable to read private key file "%s".', $privateKey));
            }

            return $contents;
        }

        return "-----BEGIN PRIVATE KEY-----\n"
            . chunk_split(preg_replace('/\s+/', '', $privateKey), 64, "\n")
            . "-----END PRIVATE KEY-----\n";
    }
}
