<?php

declare(strict_types=1);

namespace AppleSignIn\Exception;

/**
 * Thrown when an identity token cannot be trusted (bad signature, expired,
 * wrong issuer/audience/nonce, malformed JWT, ...).
 */
class InvalidTokenException extends AppleSignInException
{
}
