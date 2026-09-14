<?php

declare(strict_types=1);

namespace AppleSignIn\Tests;

use AppleSignIn\ClientSecretGenerator;
use AppleSignIn\Exception\AppleSignInException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;

final class ClientSecretGeneratorTest extends TestCase
{
    public function testGeneratesValidEs256Jwt(): void
    {
        $privatePem = TestKeys::ec();
        $publicPem = openssl_pkey_get_details(openssl_pkey_get_private($privatePem))['key'];

        $issuedAt = time();

        $secret = ClientSecretGenerator::generate(
            'TEAM1234AB',
            'com.example.app',
            'KEY1234567',
            $privatePem,
            3600,
            $issuedAt,
        );

        $parts = explode('.', $secret);
        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('ES256', $header['alg']);
        self::assertSame('KEY1234567', $header['kid']);

        $payload = JWT::decode($secret, new Key($publicPem, 'ES256'));

        self::assertSame('TEAM1234AB', $payload->iss);
        self::assertSame('com.example.app', $payload->sub);
        self::assertSame('https://appleid.apple.com', $payload->aud);
        self::assertSame($issuedAt, (int) $payload->iat);
        self::assertSame($issuedAt + 3600, (int) $payload->exp);
    }

    public function testRejectsTtlOverSixMonths(): void
    {
        $this->expectException(AppleSignInException::class);
        ClientSecretGenerator::generate(
            'TEAM1234AB',
            'com.example.app',
            'KEY1234567',
            TestKeys::ec(),
            ClientSecretGenerator::MAX_TTL + 1,
        );
    }
}
