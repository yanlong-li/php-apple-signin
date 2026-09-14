<?php

declare(strict_types=1);

namespace AppleSignIn\Exception;

use RuntimeException;

/**
 * Base exception for every error raised while validating a Sign In with Apple
 * identity token (malformed token, invalid signature, wrong audience, ...).
 */
class AppleSignInException extends RuntimeException
{
}
