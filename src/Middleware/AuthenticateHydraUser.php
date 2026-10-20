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
 * Router alias: `auth.hydra`.
 *
 * Requires a valid Hydra access token with a non-empty `sub` claim
 * (a human user, not a pure client-credentials token).
 */
class AuthenticateHydraUser
{
    public function __construct(private readonly TokenVerifier $verifier)
    {
    }

    public function handle(Request $request, Closure $next): Response
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

        if ($principal->sub === null || $principal->sub === '') {
            Log::info('hydra-auth: token has no subject');

            return response()->json(['error' => 'invalid_token'], 401);
        }

        $request->attributes->set('hydra', $principal);

        return $next($request);
    }
}
