<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use RuntimeException;
use Throwable;

/**
 * The server-side session record could not be written after the host session
 * was regenerated.
 *
 * The regenerated host session has been destroyed by the time this is thrown.
 * Authentication fails closed: the alternative is a session the host guard
 * accepts and vouch has no record of, which would pass every host check and
 * fail vouch's per-request read for as long as it lives.
 */
final class SessionRotationFailed extends RuntimeException
{
    public static function after(Throwable $previous): self
    {
        return new self(
            'Vouch could not record the rotated session. The regenerated host session has '
            . 'been destroyed and authentication refused, because a guard-authenticated '
            . 'session with no vouch record is worse than a failed login.',
            0,
            $previous,
        );
    }
}
