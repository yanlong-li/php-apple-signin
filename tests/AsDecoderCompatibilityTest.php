<?php

declare(strict_types=1);

namespace AppleSignIn\Tests;

use AppleSignIn\ASDecoder;
use AppleSignIn\ASPayload;
use AppleSignIn\AppleSignInDecoder;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;

/**
 * Covers the legacy static ASDecoder API fed with a raw JWKS document,
 * as fetched from https://appleid.apple.com/auth/keys.
 */
final class AsDecoderCompatibilityTest extends TestCase
{
    private string $privatePem;
    private string $jwksJson;

    protected function setUp(): void
    {
        [$this->privatePem, $publicPem] = TestKeys::rsa();

        $details = openssl_pkey_get_details(openssl_pkey_get_public($publicPem));
        $encode = static fn (string $value): string => rtrim(
            strtr(base64_encode($value), '+/', '-_'),
            '=',
        );

        $this->jwksJson = json_encode([
            'keys' => [
                [
                    'kty' => 'RSA',
                    'kid' => TestKeys::KID,
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'n' => $encode($details['rsa']['n']),
                    'e' => $encode($details['rsa']['e']),
                ],
            ],
        ], JSON_THROW_ON_ERROR);
    }

    protected function tearDown(): void
    {
        ASDecoder::$responseKeys = '';
    }

    public function testLegacyStaticApiDecodesWithRawJwks(): void
    {
        $identityToken = JWT::encode([
            'iss' => AppleSignInDecoder::ISSUER,
            'aud' => 'com.example.app',
            'exp' => time() + 3600,
            'iat' => time(),
            'sub' => '001234.abc',
            'email' => 'user@example.com',
        ], $this->privatePem, 'RS256', TestKeys::KID);

        ASDecoder::$responseKeys = $this->jwksJson;

        $payload = ASDecoder::getAppleSignInPayload($identityToken);

        self::assertInstanceOf(ASPayload::class, $payload);
        self::assertSame('001234.abc', $payload->getUser());
        self::assertSame('user@example.com', $payload->getEmail());
        self::assertTrue($payload->verifyUser('001234.abc'));
        self::assertSame('user@example.com', $payload->email);
    }
}
