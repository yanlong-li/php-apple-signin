# Sign In with Apple for PHP — php-apple-signin

[![Latest Version](https://img.shields.io/packagist/v/yanlongli/php-apple-signin?label=packagist&style=flat-square)](https://packagist.org/packages/yanlongli/php-apple-signin)
[![PHP Version](https://img.shields.io/packagist/php-v/yanlongli/php-apple-signin?style=flat-square)](https://packagist.org/packages/yanlongli/php-apple-signin)
[![Downloads](https://img.shields.io/packagist/dt/yanlongli/php-apple-signin?style=flat-square)](https://packagist.org/packages/yanlongli/php-apple-signin)
[![License](https://img.shields.io/packagist/l/yanlongli/php-apple-signin?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/yanlong-li/php-apple-signin/php.yml?branch=master&style=flat-square)](https://github.com/yanlong-li/php-apple-signin/actions)

Server-side PHP SDK for [Sign In with Apple](https://developer.apple.com/sign-in-with-apple/) (通过 Apple 登录 / 苹果登录 / 苹果登陆). Verify Apple identity tokens (JWT) from iOS, macOS and the web using Apple's public JWKS, and generate the ES256 `client_secret` for the token and revoke REST endpoints.

PHP library to verify and parse [Sign In with Apple](https://developer.apple.com/sign-in-with-apple/) identity tokens server side, following Apple's current REST API guidance (JWKS/RS256 signature verification, issuer/audience/nonce/expiry checks), and to generate the ES256 `client_secret` needed by the server-to-server endpoints.

> PHP 服务端验证并解析「通过 Apple 登录」（苹果登录 / 苹果登陆）身份令牌（JWT）。支持从 iOS、macOS 及网页端获取的 Apple identity token（`ASAuthorizationAppleIDCredential.identityToken` / `id_token`），通过 Apple 官方 JWKS 公钥完成 RS256 签名验证，并严格按苹果最新文档校验签发者 `iss`、受众 `aud`（Bundle ID / Services ID）、`nonce` 与过期时间；同时提供 `/auth/token`、`/auth/revoke` 等服务端接口所需的 ES256 `client_secret` 生成器。可直接用于 Laravel、Symfony、Hyperf 等框架。

Parity replacement of the unmaintained `griffinledingham/php-apple-signin`（已停止维护的苹果登录库的替代实现）.

## Features / 功能特性

- Verify Apple identity token JWT signature against `https://appleid.apple.com/auth/keys` JWKS (RS256, `kid` matching)
- Enforce Apple's recommended claims: `iss`, `aud` (client ID), `exp`/`iat`/`nbf` and anti-replay `nonce`
- Typed access to `sub` (user), `email`, `email_verified`, `is_private_email`, `real_user_status`, `transfer_sub`
- PSR-16 cache and injectable Guzzle HTTP client for public keys (Guzzle 7 & 8)
- Generate ES256 `client_secret` from your `.p8` key, capped at Apple's 6-month limit
- Framework agnostic: plain PHP, Laravel, Symfony, Hyperf, ...
- PHP 8+ with full static types and a PHPUnit test suite

> 基于官方 JWKS 验证 JWT 签名；校验 iss/aud/nonce/exp；类型化读取用户标识、邮箱（含私有中继邮箱）、真实用户状态等；支持 PSR-16 缓存公钥、自定义 Guzzle；生成 ES256 client_secret；框架无关，原生 PHP / Laravel / Symfony / Hyperf 均可用。

## Requirements / 环境要求

- PHP `^8.0` with `ext-json` and `ext-openssl`
- `firebase/php-jwt` `^7.0` (v6 is not supported: CVE-2025-45769 affects all releases below v7)
- `guzzlehttp/guzzle` `^7.8 || ^8.0`

## Installation / 安装

```bash
composer require yanlongli/php-apple-signin
```

## Verify an identity token / 验证身份令牌

```php
use AppleSignIn\AppleSignInDecoder;
use AppleSignIn\ApplePublicKeyProvider;
use AppleSignIn\Exception\InvalidTokenException;

// credential.identityToken (iOS) or the "id_token" field (web)
$identityToken = $_POST['identity_token'] ?? '';

// App bundle ID (native) or Services ID (web) — enables the "aud" check
$clientId = 'com.example.app';

$decoder = new AppleSignInDecoder(new ApplePublicKeyProvider());

try {
    // Third argument: expected nonce, when your auth request used one
    $token = $decoder->decode($identityToken, $clientId /* , $nonce */);
} catch (InvalidTokenException $e) {
    http_response_code(401);
    exit($e->getMessage());
}

$userIdentifier = $token->getUserIdentifier(); // "sub" === credential.user
$email          = $token->getEmail();
$emailVerified  = $token->isEmailVerified();
$privateEmail   = $token->isPrivateEmail();

if (!$token->verifyUser($clientProvidedUser)) {
    // credential.user mismatch
}
```

The decoder performs every check recommended by Apple:

1. RS256 signature against the live JWKS at `https://appleid.apple.com/auth/keys` (`kid` matched).
2. `iss === https://appleid.apple.com`, `exp`/`iat`/`nbf` (120 s clock leeway by default).
3. `aud` equals your client ID and, when supplied, `nonce` matches the session nonce.

> 解码器完整执行苹果要求的校验：基于 Apple JWKS 的 RS256 签名验证、签发者/过期时间校验、`aud` 客户端 ID 校验以及 `nonce` 防重放校验。

### Available claim getters / Claim 读取方法

| Method | Claim |
| --- | --- |
| `getIssuer()` | `iss` |
| `getAudience()` | `aud` |
| `getUserIdentifier()` / `getUser()` | `sub` |
| `getEmail()` | `email` |
| `isEmailVerified()` | `email_verified` (bool or `"true"`) |
| `isPrivateEmail()` | `is_private_email` |
| `getNonce()` | `nonce` |
| `isNonceSupported()` | `nonce_supported` |
| `getRealUserStatus()` | `real_user_status` |
| `getTransferSub()` | `transfer_sub` |
| `getExpiresAt()` / `getIssuedAt()` / `getNotBefore()` | `exp` / `iat` / `nbf` |
| `getClaim($name)` / `getClaims()` | raw access |

## Caching Apple public keys / 缓存 Apple 公钥

Apple keys rarely rotate and should be cached. Pass any [PSR-16](https://www.php-fig.org/psr/psr-16/) cache:

```php
use AppleSignIn\ApplePublicKeyProvider;

$provider = new ApplePublicKeyProvider($guzzleClient, $psr16Cache, ttl: 3600);
$decoder  = new AppleSignInDecoder($provider);
```

A pre-fetched JWKS (JSON string, array, or an already parsed `Key` map) can be
supplied through `AppleSignIn\StaticPublicKeyProvider`.

## Generate a client_secret / 生成 client_secret

For the `/auth/token` and `/auth/revoke` endpoints, sign a JWT with the ES256
key (`AuthKey_XXXXXXXXXX.p8`) from Certificates, Identifiers & Profiles:

```php
use AppleSignIn\ClientSecretGenerator;

$clientSecret = ClientSecretGenerator::generate(
    teamId:     'TEAM1234AB',
    clientId:   'com.example.app',
    keyId:      'KEY1234567',
    privateKey: file_get_contents('/path/to/AuthKey_KEY1234567.p8'),
);
```

The private key may be a PEM string, the raw key body, or a `.p8` path. The
TTL is capped at Apple's 6-month limit (`ClientSecretGenerator::MAX_TTL`).

## Migration from v1/v2 / 从旧版本迁移

The legacy static API still works and is backed by the new implementation:

```php
use AppleSignIn\ASDecoder;

$payload = ASDecoder::getAppleSignInPayload($identityToken);
$payload->getEmail();
$payload->getUser();
$payload->verifyUser($clientUser);
```

It is deprecated: prefer `AppleSignInDecoder` (audience/nonce enforcement and
proper exceptions).

## Testing / 测试

```bash
composer test
```

## FAQ / 常见问题

See [doc/faq.md](doc/faq.md).

## Search terms / 搜索关键词

Sign In with Apple PHP, Apple ID login PHP, Apple identity token verification, Apple JWT JWKS RS256 validation PHP, `firebase/php-jwt` Apple keys, ES256 client_secret generator, `ASAuthorizationAppleIDCredential` server validation, iOS 苹果登录 PHP SDK, 苹果账号登陆服务端验证, 苹果授权登录 token 校验, 替代 `griffinledingham/php-apple-signin`.

## Changelog

### v3.0

- Requires PHP 8; `firebase/php-jwt` `^7.0`, `guzzlehttp/guzzle` `^7.8 || ^8.0`.
- New `AppleSignInDecoder` with strict issuer/audience/nonce/expiry verification and typed `IdentityToken` claims.
- PSR-16 caching and injectable Guzzle client via `ApplePublicKeyProvider`.
- New `ClientSecretGenerator` for ES256 client secrets.
- Dedicated `AppleSignInException` / `InvalidTokenException`.
- PHPUnit test suite.

### v2.0
Simplified decoding on top of `firebase/php-jwt` v6.

## License

BSD-3-Clause
