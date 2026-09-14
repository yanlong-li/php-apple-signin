<?php

declare(strict_types=1);

namespace AppleSignIn;

use AppleSignIn\Exception\AppleSignInException;
use AppleSignIn\Exception\InvalidTokenException;
use Firebase\JWT\JWT;
use Throwable;

/**
 * Verifies Sign In with Apple identity tokens according to the official REST
 * API documentation: RS256 signature against Apple JWKS, issuer, expiration,
 * audience (App/Services ID) and optional nonce.
 *
 * @see https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
 */
final class AppleSignInDecoder
{
    public const ISSUER = 'https://appleid.apple.com';
    public const ALGORITHM = 'RS256';
    public const DEFAULT_LEEWAY = 120;

    public function __construct(
        private readonly ?PublicKeyProvider $keyProvider = null,
        private readonly int $leeway = self::DEFAULT_LEEWAY,
    ) {
    }

    /**
     * @param string      $identityToken JWT from identityToken (native) or the
     *                                   id_token field (web)
     * @param string|null $clientId      Expected audience: app bundle ID or
     *                                   Services ID. When null, the audience
     *                                   claim is not enforced.
     * @param string|null $nonce         Expected nonce, when one was requested
     *                                   in the authorization request.
     *
     * @throws InvalidTokenException
     */
    public function decode(string $identityToken, ?string $clientId = null, ?string $nonce = null): IdentityToken
    {
        $provider = $this->keyProvider ?? new ApplePublicKeyProvider();

        $previousLeeway = JWT::$leeway;
        JWT::$leeway = max(JWT::$leeway, $this->leeway);

        try {
            $keySet = $provider->getKeySet();

            $payload = JWT::decode($identityToken, $keySet);
        } catch (AppleSignInException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidTokenException('Invalid Apple identity token: ' . $e->getMessage(), 0, $e);
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        $this->verifyClaims($payload, $clientId, $nonce);

        return new IdentityToken($payload);
    }

    /**
     * @throws InvalidTokenException
     */
    private function verifyClaims(object $payload, ?string $clientId, ?string $nonce): void
    {
        if (($payload->iss ?? null) !== self::ISSUER) {
            throw new InvalidTokenException('Invalid token issuer.');
        }

        if (!isset($payload->sub) || $payload->sub === '') {
            throw new InvalidTokenException('Token is missing the "sub" claim.');
        }

        if ($clientId !== null && ($payload->aud ?? null) !== $clientId) {
            throw new InvalidTokenException(sprintf(
                'Token audience "%s" does not match the expected client ID "%s".',
                $payload->aud ?? '',
                $clientId,
            ));
        }

        if ($nonce !== null && !hash_equals($nonce, (string) ($payload->nonce ?? ''))) {
            throw new InvalidTokenException('Token nonce does not match the expected nonce.');
        }
    }
}
