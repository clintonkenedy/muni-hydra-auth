<?php

declare(strict_types=1);

namespace Muni\HydraAuth;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Muni\HydraAuth\Middleware\AuthenticateHydraClient;
use Muni\HydraAuth\Middleware\AuthenticateHydraUser;

class HydraAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/hydra-auth.php', 'hydra-auth');

        $this->app->singleton(JwksCache::class, function (Application $app): JwksCache {
            $config = $app['config']['hydra-auth'];

            return new JwksCache(
                cache: $app['cache']->store($config['cache_store'] ?? null),
                jwksUrl: (string) $config['jwks_url'],
                ttl: (int) $config['jwks_cache_ttl'],
            );
        });

        $this->app->singleton(TokenVerifier::class, function (Application $app): TokenVerifier {
            $config = $app['config']['hydra-auth'];

            return new TokenVerifier(
                jwksCache: $app->make(JwksCache::class),
                issuer: (string) $config['issuer'],
                audience: (string) $config['audience'],
                leeway: (int) $config['leeway'],
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/hydra-auth.php' => config_path('hydra-auth.php'),
        ], 'hydra-auth-config');

        /** @var Router $router */
        $router = $this->app['router'];
        $router->aliasMiddleware('auth.hydra', AuthenticateHydraUser::class);
        $router->aliasMiddleware('hydra.client', AuthenticateHydraClient::class);
    }
}
