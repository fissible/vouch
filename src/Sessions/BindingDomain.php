<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

/**
 * Which binding a derived value is for.
 *
 * Required rather than defaulted, deliberately. Two columns bind to the same
 * host session — auth_sessions.session_binding and auth_attempts.bound_context
 * — and if both derived the same value, one escaping into a log or an error
 * message would immediately be a valid lookup key for the other.
 *
 * A default would make that cross-context derivation something a future caller
 * can write silently and a reviewer can miss. Requiring the argument makes it
 * unwritable: the type system carries the rule rather than a docblock.
 */
enum BindingDomain: string
{
    /** auth_sessions.session_binding — an established session. */
    case Session = 'session';

    /** auth_attempts.bound_context — an in-progress authentication attempt. */
    case Attempt = 'attempt';
}
