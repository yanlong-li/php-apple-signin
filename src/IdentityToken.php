<?php

declare(strict_types=1);

namespace AppleSignIn;

use stdClass;

/**
 * Typed view over the claims contained in a verified Sign In with Apple
 * identity token (JWT payload).
 *
 * @see https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
 */
final class IdentityToken
{
    private stdClass $claims;

    public function __construct(stdClass $claims)
    {
        $this->claims = $claims;
    }

    /**
     * Apple team identifier-scoped Sign In with Apple key, e.g. "https://appleid.apple.com".
     */
    public function getIssuer(): string
    {
        return (string) ($this->claims->iss ?? '');
    }

    /**
     * Client App ID (Services ID for web, bundle ID for native apps).
     */
    public function getAudience(): string
    {
        return (string) ($this->claims->aud ?? '');
    }

    /**
     * Expiration time (unix timestamp).
     */
    public function getExpiresAt(): ?int
    {
        return isset($this->claims->exp) ? (int) $this->claims->exp : null;
    }

    /**
     * Issued-at time (unix timestamp).
     */
    public function getIssuedAt(): ?int
    {
        return isset($this->claims->iat) ? (int) $this->claims->iat : null;
    }

    /**
     * Not-before time (unix timestamp).
     */
    public function getNotBefore(): ?int
    {
        return isset($this->claims->nbf) ? (int) $this->claims->nbf : null;
    }

    /**
     * Unique identifier for the signed-in user. Stable per development team.
     */
    public function getUserIdentifier(): string
    {
        return (string) ($this->claims->sub ?? '');
    }

    /**
     * Unique identifier for the signed-in user (alias of {@see getUserIdentifier()}).
     */
    public function getUser(): string
    {
        return $this->getUserIdentifier();
    }

    /**
     * Private email relay or the user real address. Only present on first
     * sign-in or when the user shares their email.
     */
    public function getEmail(): ?string
    {
        return isset($this->claims->email) ? (string) $this->claims->email : null;
    }

    /**
     * Whether Apple verified the email address ("verified" or unknown/null).
     */
    public function isEmailVerified(): bool
    {
        return ($this->claims->email_verified ?? false) === true
            || ($this->claims->email_verified ?? '') === 'true';
    }

    /**
     * "true" when the email is a private @privaterelay.appleid.com address.
     */
    public function isPrivateEmail(): bool
    {
        return ($this->claims->is_private_email ?? false) === true
            || ($this->claims->is_private_email ?? '') === 'true';
    }

    /**
     * Nonce echoed back by Apple, when one was sent in the authorization
     * request. Should match the nonce of the current session.
     */
    public function getNonce(): ?string
    {
        return isset($this->claims->nonce) ? (string) $this->claims->nonce : null;
    }

    /**
     * Number of times the customer transferred the identifier through the
     * "Sign in with Apple" migration flow.
     */
    public function getTransferSub(): ?string
    {
        return isset($this->claims->transfer_sub) ? (string) $this->claims->transfer_sub : null;
    }

    /**
     * Real-user status: 0 unsupported, 1 unknown, 2 likely real.
     */
    public function getRealUserStatus(): ?int
    {
        return isset($this->claims->real_user_status) ? (int) $this->claims->real_user_status : null;
    }

    /**
     * Whether Apple supports the nonce claim for the user's account.
     */
    public function isNonceSupported(): bool
    {
        return ($this->claims->nonce_supported ?? false) === true
            || ($this->claims->nonce_supported ?? '') === 'true';
    }

    /**
     * Raw decoded claim, or null when absent.
     *
     * @return mixed
     */
    public function getClaim(string $name)
    {
        return $this->claims->{$name} ?? null;
    }

    /**
     * All decoded claims.
     */
    public function getClaims(): stdClass
    {
        return clone $this->claims;
    }

    /**
     * Backward-compatible comparison with the "user" identifier handed to the
     * client by ASAuthorizationAppleIDCredential.
     */
    public function verifyUser(string $user): bool
    {
        return hash_equals($this->getUserIdentifier(), $user);
    }
}
