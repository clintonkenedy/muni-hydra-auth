# muni/hydra-auth

Laravel middleware package that verifies [Ory Hydra](https://www.ory.sh/hydra/) JWT access tokens against the Hydra JWKS endpoint (RS256 only), with JWKS caching, stale-while-revalidate fallback, and single refetch on unknown `kid`.

> **Requirement:** Hydra must issue JWT access tokens, i.e. run with
> `strategies.access_token=jwt` (`STRATEGIES_ACCESS_TOKEN=jwt`). Opaque
> access tokens cannot be verified by this package.

## Installation

### From GitHub (production)

Add a VCS repository to your application's `composer.json`:

```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "git@github.com:MuniPuno/muni-hydra-auth.git"
        }
    ]
}
```

```bash
composer require muni/hydra-auth
```

### From a local checkout (development)

```json
{
    "repositories": [
        {
            "type": "path",
            "url": "../../muni-hydra-auth",
            "options": { "symlink": true }
        }
    ]
}
```

```bash
composer require muni/hydra-auth:@dev
```

The service provider is auto-discovered.

## Configuration

Publish the config file (optional — env vars are enough for most setups):

```bash
php artisan vendor:publish --tag=hydra-auth-config
```

Environment variables:

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `HYDRA_ISSUER` | yes | — | Hydra public URL; must match the token `iss` claim exactly. |
| `HYDRA_AUDIENCE` | yes | — | Accepted when contained in `aud` **or** equal to the `client_id` claim. |
| `HYDRA_JWKS_URL` | no | `{HYDRA_ISSUER}/.well-known/jwks.json` | JWKS endpoint. |
| `HYDRA_JWKS_CACHE_TTL` | no | `3600` | JWKS cache TTL in seconds. |
| `HYDRA_LEEWAY` | no | `10` | Clock-skew leeway in seconds for `exp`/`nbf`. |
| `HYDRA_CACHE_STORE` | no | app default | Laravel cache store used for the JWKS. |

## Usage

Two router middleware aliases are registered:

### `auth.hydra` — authenticated user

Requires a valid token with a non-empty `sub` claim.

```php
Route::middleware('auth.hydra')->get('/api/user', function (Request $request) {
    $principal = $request->attributes->get('hydra'); // Muni\HydraAuth\HydraPrincipal

    return ['sub' => $principal->sub, 'scopes' => $principal->scopes];
});
```

### `hydra.client:scope[,scope...]` — machine client with scopes

Requires a valid token carrying **all** listed scopes.

```php
Route::middleware('hydra.client:personas.read')->get('/api/personas', ...);
Route::middleware('hydra.client:personas.read,personas.write')->post('/api/personas', ...);
```

Both middlewares attach the verified principal to the request:

```php
$principal = $request->attributes->get('hydra');
$principal->sub;      // ?string
$principal->clientId; // ?string
$principal->scopes;   // list<string> — parsed from `scp` (array) or `scope` (space-separated)
$principal->claims;   // array — raw token claims
```

## Error responses

| Condition | Response |
| --- | --- |
| Missing/invalid/expired token, wrong issuer or audience, no `sub` (user middleware) | `401 {"error":"invalid_token"}` — reason logged via `Log::info`, never leaked to the body |
| Missing required scope (client middleware) | `403 {"error":"insufficient_scope"}` |
| JWKS endpoint unreachable and no cached copy | `503 {"error":"jwks_unavailable"}` |

## JWKS behavior

- JWKS cached for `jwks_cache_ttl` seconds in the configured cache store.
- A second stale copy is kept without TTL: if a refetch fails, the last known
  good key set keeps serving traffic (stale-while-revalidate).
- A token with an unknown `kid` triggers exactly one forced refetch (key
  rotation) before being rejected.

## Testing

```bash
composer install
vendor/bin/phpunit
```
