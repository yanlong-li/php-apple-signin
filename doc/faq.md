# FAQ.

## SSL certificate problem: unable to get local issuer certificate
To ensure data security, Guzzle verifies the TLS certificate by default. This error means your PHP environment is missing an up-to-date CA bundle. See https://curl.se/docs/sslcerts.html, download https://curl.se/ca/cacert.pem, and configure `php.ini`:

```ini
curl.cainfo = "/your/path/cacert.pem"
openssl.cafile = "/your/path/cacert.pem"
```

## Which claims should I verify?
Verify the RS256 signature against `https://appleid.apple.com/auth/keys`, then check `iss` (`https://appleid.apple.com`), `aud` (your bundle/Services ID), `exp`, and the `nonce` when one was requested. `AppleSignInDecoder::decode()` performs all of these checks for you.

## email / email_verified missing
Apple only includes `email`, `email_verified` and `is_private_email` on the first authorization. On subsequent logins use the stable `sub` identifier (see `IdentityToken::getUserIdentifier()`); to get the email again the user must stop using Sign In with Apple in their Apple ID settings and sign in again.
