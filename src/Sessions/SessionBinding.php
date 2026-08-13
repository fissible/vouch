<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use RuntimeException;

/**
 * Derives the stored binding key for a host session.
 *
 * The host session ID is a bearer credential: anyone holding it is the session.
 * Storing it raw would turn any read of auth_sessions — SQL injection, a
 * backup, a read replica, a support export — into a pile of usable session
 * credentials. This is the same reasoning that hashes OTPs and recovery codes,
 * applied to the one other bearer value the schema touches.
 *
 * Keyed to APP_KEY, so rotating the key invalidates every session. That is
 * acceptable and already true of Laravel's encrypted session cookies.
 */
final class SessionBinding
{
    public static function for(string $hostSessionId, BindingDomain $domain): string
    {
        $key = config('app.key');

        if (! is_string($key) || $key === '') {
            throw new RuntimeException(
                'Vouch requires APP_KEY to be set: it keys the session binding HMAC.',
            );
        }

        /*
         * The domain is part of the HMAC input, separated by a NUL byte so that
         * no domain/session-ID pair can be confused with another. Without the
         * separator, domain "sessiona" + id "bc" and domain "session" + id "abc"
         * would derive the same value.
         */
        return hash_hmac('sha256', $domain->value . "\0" . $hostSessionId, $key);
    }
}
