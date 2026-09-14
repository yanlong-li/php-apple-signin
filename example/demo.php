<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use AppleSignIn\ApplePublicKeyProvider;
use AppleSignIn\AppleSignInDecoder;
use AppleSignIn\ClientSecretGenerator;

// ASAuthorizationAppleIDCredential: credential.identityToken
$identityToken = 'example_encoded_jwt';

// Your app bundle ID (native) or Services ID (web). Passing it enables the
// "aud" claim check recommended by Apple.
$clientId = 'com.example.app';

// Optional: inject a Guzzle client and/or a PSR-16 cache for Apple public keys.
$keyProvider = new ApplePublicKeyProvider();
$decoder = new AppleSignInDecoder($keyProvider);

try {
    $token = $decoder->decode($identityToken, $clientId /* , $expectedNonce */);
} catch (\AppleSignIn\Exception\InvalidTokenException $e) {
    http_response_code(401);
    exit('Invalid identity token: ' . $e->getMessage());
}

$userIdentifier = $token->getUserIdentifier(); // credential.user / "sub"
$email = $token->getEmail();
$isPrivateEmail = $token->isPrivateEmail();
$isEmailVerified = $token->isEmailVerified();

// Server-to-server calls (token / revoke endpoints): build an ES256
// client_secret with your Sign In with Apple .p8 key.
$clientSecret = ClientSecretGenerator::generate(
    teamId:     'TEAM1234AB',
    clientId:   $clientId,
    keyId:      'KEY1234567',
    privateKey: file_get_contents('/path/to/AuthKey_KEY1234567.p8'),
);

var_dump($userIdentifier, $email, $isPrivateEmail, $isEmailVerified, $clientSecret);
