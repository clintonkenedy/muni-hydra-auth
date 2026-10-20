<?php

declare(strict_types=1);

namespace Muni\HydraAuth\Exceptions;

/**
 * Thrown when a token is missing, malformed, badly signed, expired,
 * or fails issuer/audience validation. Maps to HTTP 401 semantics.
 */
class InvalidTokenException extends \RuntimeException
{
}
