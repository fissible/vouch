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

    /** Submitted-identifier authentication failure state. */
    case ThrottleIdentifier = 'throttle.identifier';

    /** Recovery-path failure state, separate from ordinary authentication. */
    case ThrottleRecovery = 'throttle.recovery';

    /** Challenge-issuance volume, charged before target resolution. */
    case ThrottleIssuance = 'throttle.issuance';

    /** Advisory IPv4 breadth state. */
    case ThrottleIpV4 = 'throttle.ipv4';

    /** Advisory IPv6 state bucketed to the network's first 64 bits. */
    case ThrottleIpV6 = 'throttle.ipv6-prefix-64';

    /** Deduplication marker for one canonical IP and submitted identifier. */
    case ThrottleIpIdentifier = 'throttle.ip-identifier';

    /** Tenant-wide advisory state. */
    case ThrottleTenant = 'throttle.tenant';

    /** Package-wide advisory state. */
    case ThrottleGlobal = 'throttle.global';

    /** Identifier-control ceremony volume, distinct from login issuance. */
    case ThrottleCeremony = 'throttle.ceremony';
}
