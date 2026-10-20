<?php

declare(strict_types=1);

namespace Muni\HydraAuth;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Http;
use Muni\HydraAuth\Exceptions\JwksUnavailableException;

/**
 * Caches the JWKS fetched from Hydra.
 *
 * Two cache entries are kept: a fresh entry bounded by the configured TTL
 * and a stale entry with no TTL, so that a failing refetch can still be
 * served from the last known good key set (stale-while-revalidate).
 */
class JwksCache
{
    private const FRESH_KEY = 'hydra-auth:jwks';

    private const STALE_KEY = 'hydra-auth:jwks:stale';

    public function __construct(
        private readonly CacheRepository $cache,
        private readonly string $jwksUrl,
        private readonly int $ttl,
    ) {
    }

    /**
     * Return the JWKS as an array (`['keys' => [...]]`).
     *
     * @throws JwksUnavailableException when the fetch fails and no copy exists
     *
     * @return array<string, mixed>
     */
    public function keys(bool $forceRefresh = false): array
    {
        if ($forceRefresh) {
            $this->cache->forget(self::FRESH_KEY);
        }

        $fresh = $this->cache->get(self::FRESH_KEY);

        if (is_array($fresh)) {
            return $fresh;
        }

        try {
            $jwks = $this->fetch();
        } catch (\Throwable $e) {
            $stale = $this->cache->get(self::STALE_KEY);

            if (is_array($stale)) {
                return $stale;
            }

            throw new JwksUnavailableException(
                'JWKS fetch failed and no cached copy is available: '.$e->getMessage(),
                previous: $e,
            );
        }

        $this->cache->put(self::FRESH_KEY, $jwks, $this->ttl);
        $this->cache->forever(self::STALE_KEY, $jwks);

        return $jwks;
    }

    /**
     * Drop the fresh entry so the next read refetches. The stale copy is
     * kept on purpose as the stale-while-revalidate fallback.
     */
    public function forget(): void
    {
        $this->cache->forget(self::FRESH_KEY);
    }

    /**
     * @return array<string, mixed>
     */
    private function fetch(): array
    {
        $response = Http::get($this->jwksUrl);

        if ($response->failed()) {
            throw new \RuntimeException('JWKS endpoint returned HTTP '.$response->status());
        }

        $jwks = $response->json();

        if (! is_array($jwks) || ! isset($jwks['keys']) || ! is_array($jwks['keys'])) {
            throw new \RuntimeException('JWKS endpoint returned an invalid document');
        }

        return $jwks;
    }
}
