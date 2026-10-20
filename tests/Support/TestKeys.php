<?php

declare(strict_types=1);

namespace Muni\HydraAuth\Tests\Support;

use Firebase\JWT\JWT;

/**
 * Generates RSA-2048 keypairs with openssl, exposes them as JWK arrays,
 * and signs test tokens with configurable claims.
 */
final class TestKeys
{
    public const PRIMARY_KID = 'test-key-1';

    public const SECONDARY_KID = 'test-key-2';

    /** @var array<string, array{private: string, jwk: array<string, string>}> */
    private static array $pairs = [];

    /**
     * @return array{private: string, jwk: array<string, string>}
     */
    public static function pair(string $kid = self::PRIMARY_KID): array
    {
        return self::$pairs[$kid] ??= self::generate($kid);
    }

    /**
     * @return array<string, mixed> JWKS document, e.g. ['keys' => [...]]
     */
    public static function jwks(string ...$kids): array
    {
        $kids = $kids ?: [self::PRIMARY_KID];

        return [
            'keys' => array_map(fn (string $kid): array => self::pair($kid)['jwk'], $kids),
        ];
    }

    /**
     * Sign a token. Default claims are valid for the test issuer/audience;
     * override any claim, or set it to null to remove it.
     *
     * @param array<string, mixed> $claims
     */
    public static function token(
        array $claims = [],
        string $kid = self::PRIMARY_KID,
        ?string $privateKey = null,
    ): string {
        $now = time();

        $defaults = [
            'iss' => 'https://idp.test',
            'aud' => 'sistrans',
            'sub' => 'user-123',
            'client_id' => 'sistrans-front',
            'scope' => 'personas.read',
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + 300,
        ];

        $payload = array_filter(
            array_merge($defaults, $claims),
            static fn ($value): bool => $value !== null,
        );

        return JWT::encode($payload, $privateKey ?? self::pair($kid)['private'], 'RS256', $kid);
    }

    /**
     * @return array{private: string, jwk: array<string, string>}
     */
    private static function generate(string $kid): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            throw new \RuntimeException('openssl failed to generate an RSA keypair');
        }

        openssl_pkey_export($resource, $privateKeyPem);

        $details = openssl_pkey_get_details($resource);

        return [
            'private' => $privateKeyPem,
            'jwk' => [
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => 'RS256',
                'kid' => $kid,
                'n' => self::base64Url($details['rsa']['n']),
                'e' => self::base64Url($details['rsa']['e']),
            ],
        ];
    }

    private static function base64Url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
