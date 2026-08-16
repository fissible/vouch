<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use InvalidArgumentException;
use RuntimeException;

/**
 * Derives stored HMAC keys for bearer bindings and opaque throttle subjects.
 *
 * The host session ID is a bearer credential: anyone holding it is the session.
 * Storing it raw would turn any read of auth_sessions — SQL injection, a
 * backup, a read replica, a support export — into a pile of usable session
 * credentials. This is the same reasoning that hashes OTPs and recovery codes,
 * applied to the one other bearer value the schema touches.
 *
 * Keyed to APP_KEY, so rotating the key invalidates every session and attempt.
 * That is acceptable and already true of Laravel's encrypted session cookies.
 * For throttle domains the same rotation resets counters and lockouts. That is
 * a rare, operator-controlled bypass rather than a benign invalidation, so the
 * operational documentation must name it and tests pin the dependency.
 */
final class SessionBinding
{
    public static function for(string $hostSessionId, BindingDomain $domain): string
    {
        /*
         * The domain is part of the HMAC input, separated by a NUL byte so that
         * no domain/session-ID pair can be confused with another. Without the
         * separator, domain "sessiona" + id "bc" and domain "session" + id "abc"
         * would derive the same value.
         */
        return self::hmac($domain->value . "\0" . $hostSessionId);
    }

    /**
     * Derive a key from explicit, unambiguous protocol segments.
     *
     * Count and byte-length prefixes make segment boundaries structural. A
     * caller cannot make ["a", "\\0b"] collide with ["a\\0", "b"], and a
     * nullable value must be represented with an explicit marker segment rather
     * than flattened into an empty string.
     */
    public static function forSegments(BindingDomain $domain, string ...$segments): string
    {
        if ($segments === []) {
            throw new InvalidArgumentException(
                'A segmented Vouch binding requires at least one explicit segment.',
            );
        }

        $input = $domain->value . "\0" . pack('N', count($segments));

        foreach ($segments as $segment) {
            $input .= "\0" . pack('N', strlen($segment)) . $segment;
        }

        return self::hmac($input);
    }

    private static function hmac(string $input): string
    {
        $key = config('app.key');

        if (! is_string($key) || $key === '') {
            throw new RuntimeException(
                'Vouch requires APP_KEY to be set: it keys binding and throttle HMACs.',
            );
        }

        return hash_hmac('sha256', $input, $key);
    }
}
