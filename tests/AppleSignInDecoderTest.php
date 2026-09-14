<?php

declare(strict_types=1);

namespace AppleSignIn\Tests;

use AppleSignIn\AppleSignInDecoder;
use AppleSignIn\Exception\InvalidTokenException;
use AppleSignIn\StaticPublicKeyProvider;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;

final class AppleSignInDecoderTest extends TestCase
{
    private string $privatePem;
    private array $keySet;

    protected function setUp(): void
    {
        [$this->privatePem, , $this->keySet] = TestKeys::rsa();
    }

    private function issueToken(array $claims = []): string
    {
        return JWT::encode($claims + [
            'iss' => AppleSignInDecoder::ISSUER,
            'aud' => 'com.example.app',
            'exp' => time() + 3600,
            'iat' => time(),
            'sub' => '001234.abc',
            'email' => 'user@example.com',
        ], $this->privatePem, 'RS256', TestKeys::KID);
    }

    public function testDecodesValidToken(): void
    {
        $decoder = new AppleSignInDecoder(new StaticPublicKeyProvider($this->keySet));

        $token = $decoder->decode($this->issueToken(), 'com.example.app');

        self::assertSame('001234.abc', $token->getUser());
        self::assertSame('user@example.com', $token->getEmail());
    }

    public function testVerifiesNonce(): void
    {
        $decoder = new AppleSignInDecoder(new StaticPublicKeyProvider($this->keySet));

        $token = $decoder->decode(
            $this->issueToken(['nonce' => 'abc']),
            'com.example.app',
            'abc',
        );

        self::assertSame('abc', $token->getNonce());
    }

    public function testRejectsWrongAudience(): void
    {
        $decoder = new AppleSignInDecoder(new StaticPublicKeyProvider($this->keySet));

        $this->expectException(InvalidTokenException::class);
        $decoder->decode($this->issueToken(), 'com.other.app');
    }

    public function testRejectsWrongNonce(): void
    {
        $decoder = new AppleSignInDecoder(new StaticPublicKeyProvider($this->keySet));

        $this->expectException(InvalidTokenException::class);
        $decoder->decode($this->issueToken(['nonce' => 'abc']), 'com.example.app', 'xyz');
    }

    public function testRejectsWrongIssuer(): void
    {
        $decoder = new AppleSignInDecoder(new StaticPublicKeyProvider($this->keySet));

        $this->expectException(InvalidTokenException::class);
        $decoder->decode($this->issueToken(['iss' => 'https://evil.example.com']));
    }

    public function testRejectsExpiredToken(): void
    {
        $decoder = new AppleSignInDecoder(
            new StaticPublicKeyProvider($this->keySet),
            0,
        );

        $this->expectException(InvalidTokenException::class);
        $decoder->decode($this->issueToken(['exp' => time() - 10]));
    }

    public function testRejectsGarbage(): void
    {
        $decoder = new AppleSignInDecoder(new StaticPublicKeyProvider($this->keySet));

        $this->expectException(InvalidTokenException::class);
        $decoder->decode('not-a-jwt');
    }
}
