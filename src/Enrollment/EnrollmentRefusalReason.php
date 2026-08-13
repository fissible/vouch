<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

/**
 * Why an enrollment was refused.
 *
 * Two cases rather than one because the engines genuinely diverge. On
 * MySQL and Postgres a loser blocks on the row lock, then observes the
 * committed count and refuses with CapacityExceeded. On SQLite — where
 * lockForUpdate() is a no-op and serialization comes from the database-level
 * write lock — the loser instead fails to acquire at all and refuses with
 * Contended. Both are clean refusals; a caller that cares can retry Contended.
 */
enum EnrollmentRefusalReason: string
{
    /** The write would leave more active credentials than the driver allows. */
    case CapacityExceeded = 'capacity_exceeded';

    /** Another enrollment for this (user, type) held the lock past the wait. */
    case Contended = 'contended';
}
