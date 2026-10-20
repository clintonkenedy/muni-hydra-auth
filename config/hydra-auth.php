<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Issuer
    |--------------------------------------------------------------------------
    | Public URL of the Ory Hydra instance. The `iss` claim of every access
    | token must match this value exactly.
    */
    'issuer' => env('HYDRA_ISSUER', ''),

    /*
    |--------------------------------------------------------------------------
    | JWKS URL
    |--------------------------------------------------------------------------
    | Where the JSON Web Key Set is fetched from. Defaults to the standard
    | well-known endpoint under the issuer.
    */
    'jwks_url' => env('HYDRA_JWKS_URL')
        ?: rtrim((string) env('HYDRA_ISSUER', ''), '/').'/.well-known/jwks.json',

    /*
    |--------------------------------------------------------------------------
    | Audience
    |--------------------------------------------------------------------------
    | Accepted when contained in the token `aud` claim (string or array) OR
    | when it equals the `client_id` claim.
    */
    'audience' => env('HYDRA_AUDIENCE', ''),

    /*
    |--------------------------------------------------------------------------
    | JWKS cache TTL (seconds)
    |--------------------------------------------------------------------------
    */
    'jwks_cache_ttl' => (int) env('HYDRA_JWKS_CACHE_TTL', 3600),

    /*
    |--------------------------------------------------------------------------
    | Clock skew leeway (seconds) for exp/nbf/iat validation.
    |--------------------------------------------------------------------------
    */
    'leeway' => (int) env('HYDRA_LEEWAY', 10),

    /*
    |--------------------------------------------------------------------------
    | Cache store
    |--------------------------------------------------------------------------
    | Name of the Laravel cache store used for the JWKS. Null uses the
    | application default store.
    */
    'cache_store' => env('HYDRA_CACHE_STORE'),

];
