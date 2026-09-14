<?php

declare(strict_types=1);

namespace AppleSignIn;

use AppleSignIn\Exception\AppleSignInException;

/**
 * Backward-compatible decorator around {@see IdentityToken}. New code should
 * type-hint against IdentityToken directly.
 *
 * @deprecated use AppleSignIn\IdentityToken
 */
class ASPayload
{
    public function __construct(private readonly IdentityToken $token)
    {
    }

    public function getEmail(): ?string
    {
        return $this->token->getEmail();
    }

    public function getUser(): string
    {
        return $this->token->getUser();
    }

    public function verifyUser(string $user): bool
    {
        return $this->token->verifyUser($user);
    }

    public function getToken(): IdentityToken
    {
        return $this->token;
    }

    /**
     * @return mixed
     */
    public function __get(string $name)
    {
        return $this->token->getClaim($name);
    }

    public function __set(string $name, mixed $value): void
    {
        throw new AppleSignInException(sprintf('Claim "%s" is read-only.', $name));
    }

    /**
     * @param array<int, mixed> $arguments
     *
     * @return mixed
     */
    public function __call(string $method, array $arguments)
    {
        return $this->token->{$method}(...$arguments);
    }
}
