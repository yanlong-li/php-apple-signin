<?php

declare(strict_types=1);

namespace AppleSignIn\Tests;

use AppleSignIn\IdentityToken;
use PHPUnit\Framework\TestCase;
use stdClass;

final class IdentityTokenTest extends TestCase
{
    private function token(array $claims): IdentityToken
    {
        return new IdentityToken((object) ($claims + [
            'iss' => 'https://appleid.apple.com',
            'aud' => 'com.example.app',
            'exp' => time() + 3600,
            'iat' => time(),
            'sub' => '001234.abc',
        ]));
    }

    public function testExposesTypedClaims(): void
    {
        $token = $this->token([
            'email' => 'user@privaterelay.appleid.com',
            'email_verified' => 'true',
            'is_private_email' => 'true',
            'nonce' => 'nonce-value',
            'real_user_status' => 2,
        ]);

        self::assertSame('https://appleid.apple.com', $token->getIssuer());
        self::assertSame('com.example.app', $token->getAudience());
        self::assertSame('001234.abc', $token->getUser());
        self::assertSame('user@privaterelay.appleid.com', $token->getEmail());
        self::assertTrue($token->isEmailVerified());
        self::assertTrue($token->isPrivateEmail());
        self::assertSame('nonce-value', $token->getNonce());
        self::assertSame(2, $token->getRealUserStatus());
        self::assertTrue($token->verifyUser('001234.abc'));
        self::assertFalse($token->verifyUser('someone-else'));
    }

    public function testHandlesMissingAndBooleanClaims(): void
    {
        $token = $this->token([
            'email_verified' => true,
            'is_private_email' => false,
            'nonce_supported' => true,
        ]);

        self::assertNull($token->getEmail());
        self::assertNull($token->getNonce());
        self::assertNull($token->getTransferSub());
        self::assertTrue($token->isEmailVerified());
        self::assertFalse($token->isPrivateEmail());
        self::assertTrue($token->isNonceSupported());
        self::assertInstanceOf(stdClass::class, $token->getClaims());
    }
}
