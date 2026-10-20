<?php

declare(strict_types=1);

namespace Muni\HydraAuth\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Muni\HydraAuth\HydraAuthServiceProvider;
use Muni\HydraAuth\HydraPrincipal;
use Muni\HydraAuth\Tests\Support\TestKeys;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected const JWKS_URL = 'https://idp.test/.well-known/jwks.json';

    protected function getPackageProviders($app): array
    {
        return [HydraAuthServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('hydra-auth.issuer', 'https://idp.test');
        $app['config']->set('hydra-auth.audience', 'sistrans');
        $app['config']->set('hydra-auth.jwks_url', self::JWKS_URL);
        $app['config']->set('hydra-auth.jwks_cache_ttl', 3600);
        $app['config']->set('hydra-auth.leeway', 10);
    }

    protected function defineRoutes($router): void
    {
        $router->get('/api/user-protected', function (Request $request) {
            /** @var HydraPrincipal $principal */
            $principal = $request->attributes->get('hydra');

            return response()->json([
                'sub' => $principal->sub,
                'scopes' => $principal->scopes,
            ]);
        })->middleware('auth.hydra');

        $router->get('/api/client-protected', function (Request $request) {
            /** @var HydraPrincipal $principal */
            $principal = $request->attributes->get('hydra');

            return response()->json([
                'client_id' => $principal->clientId,
                'scopes' => $principal->scopes,
            ]);
        })->middleware('hydra.client:personas.read');
    }

    /**
     * Fake the JWKS endpoint with a fixed document.
     *
     * @param array<string, mixed>|null $jwks
     */
    protected function fakeJwks(?array $jwks = null): void
    {
        $jwks ??= TestKeys::jwks();

        Http::fake([self::JWKS_URL => Http::response($jwks, 200)]);
    }

    protected function fakeJwksFailure(): void
    {
        Http::fake([self::JWKS_URL => Http::response('', 500)]);
    }
}
