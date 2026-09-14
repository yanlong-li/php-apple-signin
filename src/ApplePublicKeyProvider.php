<?php

declare(strict_types=1);

namespace AppleSignIn;

use Firebase\JWT\JWK;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\RequestOptions;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException as CacheException;

/**
 * Downloads Apple public keys from https://appleid.apple.com/auth/keys,
 * optionally caching them through a PSR-16 cache.
 */
final class ApplePublicKeyProvider implements PublicKeyProvider
{
    public const KEYS_URL = 'https://appleid.apple.com/auth/keys';
    public const CACHE_KEY = 'apple_signin_public_keys_v1';
    public const DEFAULT_TTL = 3600;

    /** @var array<string, \Firebase\JWT\Key>|null */
    private ?array $keySet = null;

    private ?string $rawKeys = null;

    public function __construct(
        private readonly ?ClientInterface $httpClient = null,
        private readonly ?CacheInterface $cache = null,
        private readonly int $defaultTtl = self::DEFAULT_TTL,
    ) {
    }

    /**
     * @throws Exception\AppleSignInException
     */
    public function getKeySet(): array
    {
        if ($this->keySet !== null) {
            return $this->keySet;
        }

        $rawKeys = $this->readFromCache();

        if ($rawKeys === null) {
            $rawKeys = $this->fetchKeys();
            $this->writeToCache($rawKeys);
        }

        $this->rawKeys = $rawKeys;

        try {
            $this->keySet = JWK::parseKeySet(
                json_decode($rawKeys, true, 512, JSON_THROW_ON_ERROR),
                AppleSignInDecoder::ALGORITHM,
            );
            return $this->keySet;
        } catch (\JsonException $e) {
            throw new Exception\AppleSignInException('Apple returned an invalid JWKS payload.', 0, $e);
        }
    }

    /**
     * Raw JWKS JSON fetched from Apple, available after {@see getKeySet()} ran.
     */
    public function getRawKeys(): ?string
    {
        return $this->rawKeys;
    }

    /**
     * @throws Exception\AppleSignInException
     */
    private function fetchKeys(): string
    {
        $client = $this->httpClient ?? new \GuzzleHttp\Client([
            RequestOptions::TIMEOUT => 10.0,
            RequestOptions::CONNECT_TIMEOUT => 5.0,
        ]);

        try {
            $response = $client->request('GET', self::KEYS_URL);
        } catch (GuzzleException $e) {
            throw new Exception\AppleSignInException('Unable to fetch Apple public keys.', 0, $e);
        }

        return (string) $response->getBody();
    }

    private function readFromCache(): ?string
    {
        if ($this->cache === null) {
            return null;
        }

        try {
            $cached = $this->cache->get(self::CACHE_KEY);
        } catch (CacheException) {
            return null;
        }

        return is_string($cached) && $cached !== '' ? $cached : null;
    }

    private function writeToCache(string $rawKeys): void
    {
        if ($this->cache === null) {
            return;
        }

        try {
            $this->cache->set(self::CACHE_KEY, $rawKeys, $this->defaultTtl);
        } catch (CacheException) {
            // A cache failure must never break token verification.
        }
    }
}
