<?php

declare(strict_types=1);

namespace Muni\HydraAuth;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Muni\HydraAuth\Exceptions\InvalidTokenException;
use Muni\HydraAuth\Exceptions\JwksUnavailableException;

/**
 * Verifies Hydra RS256 JWT access tokens against the cached JWKS.
 */
class TokenVerifier
{
    /** @var list<string> */
    private readonly array $audiences;

    /**
     * @param string|array<int, string> $audience Single audience, comma-separated
     *                                            list, or array of audiences.
     */
    public function __construct(
        private readonly JwksCache $jwksCache,
        private readonly string $issuer,
        string|array $audience,
        private readonly int $leeway = 10,
    ) {
        $this->audiences = self::normalizeAudiences($audience);
    }

    /**
     * Verify signature, issuer and time-based claims. When $checkAudience is
     * true (default) the audience check is applied as well; pass false for
     * client-credentials flows where authorization is scope-based.
     *
     * @throws InvalidTokenException    401 semantics
     * @throws JwksUnavailableException 503 semantics
     */
    public function verify(string $jwt, bool $checkAudience = true): HydraPrincipal
    {
        $kid = $this->extractKid($jwt);

        $jwks = $this->jwksCache->keys();

        // Unknown kid: the signing key may have rotated. Refetch exactly once.
        if ($kid !== null && ! $this->setContainsKid($jwks, $kid)) {
            $jwks = $this->jwksCache->keys(forceRefresh: true);

            if (! $this->setContainsKid($jwks, $kid)) {
                throw new InvalidTokenException('Token kid is not present in the JWKS');
            }
        }

        JWT::$leeway = $this->leeway;

        try {
            $decoded = JWT::decode($jwt, JWK::parseKeySet($jwks, 'RS256'));
        } catch (\Throwable $e) {
            throw new InvalidTokenException('Token decode failed: '.$e->getMessage(), previous: $e);
        }

        /** @var array<string, mixed> $claims */
        $claims = json_decode(json_encode($decoded), true);

        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new InvalidTokenException('Token issuer mismatch');
        }

        if ($checkAudience && ! $this->audienceMatches($claims)) {
            throw new InvalidTokenException('Token audience mismatch');
        }

        return HydraPrincipal::fromClaims($claims);
    }

    /**
     * Accept when ANY configured audience is contained in `aud` (string or
     * array) OR equals the `client_id` claim.
     *
     * @param array<string, mixed> $claims
     */
    private function audienceMatches(array $claims): bool
    {
        $aud = $claims['aud'] ?? [];
        $aud = is_array($aud) ? $aud : [$aud];

        foreach ($this->audiences as $audience) {
            if (in_array($audience, $aud, true)) {
                return true;
            }

            if (($claims['client_id'] ?? null) === $audience) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string|array<int, string> $audience
     *
     * @return list<string>
     */
    private static function normalizeAudiences(string|array $audience): array
    {
        $values = is_array($audience) ? $audience : explode(',', $audience);

        $normalized = [];

        foreach ($values as $value) {
            $value = trim((string) $value);

            if ($value !== '') {
                $normalized[] = $value;
            }
        }

        return $normalized;
    }

    private function extractKid(string $jwt): ?string
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new InvalidTokenException('Token is not a well-formed JWT');
        }

        $header = json_decode(JWT::urlsafeB64Decode($parts[0]), true);

        if (! is_array($header)) {
            throw new InvalidTokenException('Token header is not valid JSON');
        }

        return isset($header['kid']) ? (string) $header['kid'] : null;
    }

    /**
     * @param array<string, mixed> $jwks
     */
    private function setContainsKid(array $jwks, string $kid): bool
    {
        foreach ($jwks['keys'] ?? [] as $key) {
            if (is_array($key) && ($key['kid'] ?? null) === $kid) {
                return true;
            }
        }

        return false;
    }
}
