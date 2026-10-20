<?php

declare(strict_types=1);

namespace Muni\HydraAuth;

/**
 * Immutable value object describing the authenticated Hydra token subject.
 */
final readonly class HydraPrincipal
{
    /**
     * @param list<string>         $scopes
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public ?string $sub,
        public ?string $clientId,
        public array $scopes,
        public array $claims,
    ) {
    }

    /**
     * Build a principal from the raw token claims.
     *
     * @param array<string, mixed> $claims
     */
    public static function fromClaims(array $claims): self
    {
        return new self(
            sub: isset($claims['sub']) ? (string) $claims['sub'] : null,
            clientId: isset($claims['client_id']) ? (string) $claims['client_id'] : null,
            scopes: self::parseScopes($claims),
            claims: $claims,
        );
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * Scopes come either as an array (`scp`) or as a space-separated
     * string (`scope`); both claim names accept both shapes.
     *
     * @param array<string, mixed> $claims
     * @return list<string>
     */
    private static function parseScopes(array $claims): array
    {
        $raw = $claims['scp'] ?? $claims['scope'] ?? [];

        if (is_string($raw)) {
            $raw = preg_split('/\s+/', trim($raw), flags: PREG_SPLIT_NO_EMPTY) ?: [];
        }

        if (! is_array($raw)) {
            return [];
        }

        return array_values(array_map('strval', $raw));
    }
}
