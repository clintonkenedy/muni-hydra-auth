<?php

declare(strict_types=1);

namespace Muni\HydraAuth\Tests\Feature;

use Illuminate\Support\Facades\Http;
use Muni\HydraAuth\JwksCache;
use Muni\HydraAuth\Tests\Support\TestKeys;
use Muni\HydraAuth\Tests\TestCase;

final class JwksCacheTest extends TestCase
{
    public function test_unknown_kid_triggers_exactly_one_refetch(): void
    {
        $fetches = 0;

        // First fetch only knows the primary key; the refetch returns the
        // rotated set containing the secondary key as well.
        Http::fake(function () use (&$fetches) {
            $fetches++;

            return $fetches === 1
                ? Http::response(TestKeys::jwks(TestKeys::PRIMARY_KID), 200)
                : Http::response(TestKeys::jwks(TestKeys::PRIMARY_KID, TestKeys::SECONDARY_KID), 200);
        });

        // Prime the fresh cache with the primary-only set.
        $this->app->make(JwksCache::class)->keys();

        $token = TestKeys::token(kid: TestKeys::SECONDARY_KID);

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertOk();
        $this->assertSame(2, $fetches);
    }

    public function test_unknown_kid_after_refetch_is_rejected_with_401(): void
    {
        $this->fakeJwks(TestKeys::jwks(TestKeys::PRIMARY_KID));

        $token = TestKeys::token(kid: TestKeys::SECONDARY_KID);

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertStatus(401);
        $response->assertExactJson(['error' => 'invalid_token']);
        Http::assertSentCount(2);
    }

    public function test_fetch_failure_with_stale_cache_still_verifies(): void
    {
        $failing = false;

        Http::fake(function () use (&$failing) {
            return $failing
                ? Http::response('', 500)
                : Http::response(TestKeys::jwks(), 200);
        });

        // Populate both the fresh and stale cache entries.
        $cache = $this->app->make(JwksCache::class);
        $cache->keys();

        // Simulate fresh-entry expiry, then make the endpoint fail.
        $cache->forget();
        $failing = true;

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.TestKeys::token(),
        ]);

        $response->assertOk();
        $response->assertJson(['sub' => 'user-123']);
    }

    public function test_fetch_failure_without_cache_returns_503(): void
    {
        $this->fakeJwksFailure();

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.TestKeys::token(),
        ]);

        $response->assertStatus(503);
        $response->assertExactJson(['error' => 'jwks_unavailable']);
    }
}
