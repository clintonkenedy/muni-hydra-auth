<?php

declare(strict_types=1);

namespace Muni\HydraAuth\Tests\Feature;

use Muni\HydraAuth\Tests\Support\TestKeys;
use Muni\HydraAuth\Tests\TestCase;

final class AuthenticateHydraClientTest extends TestCase
{
    public function test_token_with_required_scope_passes(): void
    {
        $this->fakeJwks();

        $token = TestKeys::token(['scope' => 'personas.read otros.write']);

        $response = $this->getJson('/api/client-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertOk();
        $response->assertJson([
            'client_id' => 'sistrans-front',
            'scopes' => ['personas.read', 'otros.write'],
        ]);
    }

    public function test_scp_array_claim_is_parsed(): void
    {
        $this->fakeJwks();

        $token = TestKeys::token(['scope' => null, 'scp' => ['personas.read']]);

        $response = $this->getJson('/api/client-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertOk();
        $response->assertJson(['scopes' => ['personas.read']]);
    }

    public function test_missing_scope_is_rejected_with_403(): void
    {
        $this->fakeJwks();

        $token = TestKeys::token(['scope' => 'otros.write']);

        $response = $this->getJson('/api/client-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertStatus(403);
        $response->assertExactJson(['error' => 'insufficient_scope']);
    }

    public function test_invalid_token_is_rejected_with_401(): void
    {
        $this->fakeJwks();

        $response = $this->getJson('/api/client-protected', [
            'Authorization' => 'Bearer not-a-jwt',
        ]);

        $response->assertStatus(401);
        $response->assertExactJson(['error' => 'invalid_token']);
    }
}
