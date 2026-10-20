<?php

declare(strict_types=1);

namespace Muni\HydraAuth\Exceptions;

/**
 * Thrown when the JWKS cannot be fetched and no cached copy exists.
 * Maps to HTTP 503 semantics.
 */
class JwksUnavailableException extends \RuntimeException
{
}
