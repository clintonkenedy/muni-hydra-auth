<?php

declare(strict_types=1);

namespace Muni\HydraAuth\Tests\Feature;

use Muni\HydraAuth\Tests\Support\TestKeys;
use Muni\HydraAuth\Tests\TestCase;

final class AuthenticateHydraUserTest extends TestCase
{
    public function test_valid_token_passes(): void
    {
        $this->fakeJwks();

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.TestKeys::token(),
        ]);

        $response->assertOk();
        $response->assertJson(['sub' => 'user-123', 'scopes' => ['personas.read']]);
    }

    public function test_missing_token_is_rejected_with_401(): void
    {
        $this->fakeJwks();

        $response = $this->getJson('/api/user-protected');

        $response->assertStatus(401);
        $response->assertExactJson(['error' => 'invalid_token']);
    }

    public function test_invalid_signature_is_rejected_with_401(): void
    {
        $this->fakeJwks();

        // Signed with a different private key but advertising the known kid.
        $token = TestKeys::token(
            kid: TestKeys::PRIMARY_KID,
            privateKey: TestKeys::pair(TestKeys::SECONDARY_KID)['private'],
        );

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertStatus(401);
        $response->assertExactJson(['error' => 'invalid_token']);
    }

    public function test_expired_token_is_rejected_with_401(): void
    {
        $this->fakeJwks();

        $token = TestKeys::token(['exp' => time() - 3600, 'iat' => time() - 7200, 'nbf' => time() - 7200]);

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertStatus(401);
        $response->assertExactJson(['error' => 'invalid_token']);
    }

    public function test_wrong_issuer_is_rejected_with_401(): void
    {
        $this->fakeJwks();

        $token = TestKeys::token(['iss' => 'https://evil.test']);

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertStatus(401);
        $response->assertExactJson(['error' => 'invalid_token']);
    }

    public function test_wrong_audience_is_rejected_with_401(): void
    {
        $this->fakeJwks();

        $token = TestKeys::token(['aud' => 'other-api', 'client_id' => 'other-client']);

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertStatus(401);
        $response->assertExactJson(['error' => 'invalid_token']);
    }

    public function test_client_id_match_is_accepted_when_aud_does_not_contain_audience(): void
    {
        $this->fakeJwks();

        $token = TestKeys::token(['aud' => [], 'client_id' => 'sistrans']);

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertOk();
        $response->assertJson(['sub' => 'user-123']);
    }

    public function test_token_without_sub_is_rejected_with_401(): void
    {
        $this->fakeJwks();

        $token = TestKeys::token(['sub' => null]);

        $response = $this->getJson('/api/user-protected', [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertStatus(401);
        $response->assertExactJson(['error' => 'invalid_token']);
    }
}
