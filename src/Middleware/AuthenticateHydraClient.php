<?php

declare(strict_types=1);

namespace Muni\HydraAuth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Muni\HydraAuth\Exceptions\InvalidTokenException;
use Muni\HydraAuth\Exceptions\JwksUnavailableException;
use Muni\HydraAuth\TokenVerifier;
use Symfony\Component\HttpFoundation\Response;

/**
 * Router alias: `hydra.client`.
 *
 * Requires a valid Hydra access token carrying every scope passed as a
 * middleware parameter, e.g. `hydra.client:personas.read`.
 */
class AuthenticateHydraClient
{
    public function __construct(private readonly TokenVerifier $verifier)
    {
    }

    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        $token = $request->bearerToken();

        if ($token === null || $token === '') {
            Log::info('hydra-auth: missing bearer token');

            return response()->json(['error' => 'invalid_token'], 401);
        }

        try {
            $principal = $this->verifier->verify($token);
        } catch (JwksUnavailableException $e) {
            Log::info('hydra-auth: JWKS unavailable: '.$e->getMessage());

            return response()->json(['error' => 'jwks_unavailable'], 503);
        } catch (InvalidTokenException $e) {
            Log::info('hydra-auth: invalid token: '.$e->getMessage());

            return response()->json(['error' => 'invalid_token'], 401);
        }

        foreach ($scopes as $scope) {
            if (! $principal->hasScope($scope)) {
                Log::info("hydra-auth: token is missing required scope [{$scope}]");

                return response()->json(['error' => 'insufficient_scope'], 403);
            }
        }

        $request->attributes->set('hydra', $principal);

        return $next($request);
    }
}
