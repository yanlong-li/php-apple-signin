<?php

declare(strict_types=1);

namespace AppleSignIn\Tests;

use Firebase\JWT\Key;

/**
 * Generates throw-away RSA/EC keys for the test suite.
 */
final class TestKeys
{
    public const KID = 'TESTKEY123';

    /**
     * @return array<string, string>
     */
    private static function opensslConfig(): array
    {
        $candidate = dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . 'extras'
            . DIRECTORY_SEPARATOR . 'ssl' . DIRECTORY_SEPARATOR . 'openssl.cnf';

        return is_file($candidate) ? ['config' => $candidate] : [];
    }

    public static function rsa(): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ] + self::opensslConfig());

        openssl_pkey_export($resource, $privatePem, null, self::opensslConfig());
        $details = openssl_pkey_get_details($resource);

        return [$privatePem, $details['key'], [self::KID => new Key($details['key'], 'RS256')]];
    }

    public static function ec(): string
    {
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ] + self::opensslConfig());

        openssl_pkey_export($resource, $privatePem, null, self::opensslConfig());

        return $privatePem;
    }
}
