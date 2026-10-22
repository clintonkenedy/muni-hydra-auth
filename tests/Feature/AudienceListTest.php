<?php

declare(strict_types=1);

namespace Muni\HydraAuth\Tests\Feature;

use Muni\HydraAuth\Tests\Support\TestKeys;
use Muni\HydraAuth\Tests\TestCase;

/**
 * S1: `hydra-auth.audience` accepts a comma-separated list or array, and
 * `hydra.client` skips the audience check (scope is the authorization).
 */
final class AudienceListTest extends TestCase
{
    public function test_comma_separated_list_accepts_second_entry(): void
    {
        config()->set('hydra-auth.audience', 'sistrans,core-spa');
        $this->fakeJwks();

        $token = TestKeys::token(['aud' => 'core-spa', 'client_id' => 'other-client']);

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertOk();
        $response->assertJson(['sub' => 'user-123']);
    }

    public function test_array_audience_accepts_second_entry(): void
    {
        config()->set('hydra-auth.audience', ['sistrans', 'core-spa']);
        $this->fakeJwks();

        $token = TestKeys::token(['aud' => ['core-spa'], 'client_id' => 'other-client']);

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertOk();
    }

    public function test_user_middleware_rejects_non_listed_audience_with_401(): void
    {
        config()->set('hydra-auth.audience', 'sistrans,core-spa');
        $this->fakeJwks();

        $token = TestKeys::token(['aud' => 'other-api', 'client_id' => 'other-client']);

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertStatus(401);
        $response->assertExactJson(['error' => 'invalid_token']);
    }

    public function test_client_token_without_aud_but_with_scope_passes_client_middleware(): void
    {
        $this->fakeJwks();

        // client_credentials token: no aud, non-matching client_id, has scope.
        $token = TestKeys::token([
            'aud' => null,
            'client_id' => 'm2m-client',
            'scope' => 'personas.read',
        ]);

        $response = $this->getJson('/api/client-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertOk();
        $response->assertJson(['client_id' => 'm2m-client']);
    }

    public function test_client_token_without_required_scope_is_still_rejected_with_403(): void
    {
        $this->fakeJwks();

        $token = TestKeys::token([
            'aud' => null,
            'client_id' => 'm2m-client',
            'scope' => 'otros.write',
        ]);

        $response = $this->getJson('/api/client-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertStatus(403);
        $response->assertExactJson(['error' => 'insufficient_scope']);
    }
}
