<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

use RuntimeException;
use Throwable;

/**
 * An enrollment was refused, leaving nothing written.
 *
 * Typed rather than a raw QueryException: a contended lock surfaces as a driver
 * error on every engine — MySQL 1205, Postgres 55P03, SQLite 5 — and letting
 * that reach a caller would make "somebody else is enrolling right now"
 * indistinguishable from a database outage.
 */
final class EnrollmentRefused extends RuntimeException
{
    private function __construct(
        string $message,
        public readonly EnrollmentRefusalReason $reason,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function capacityExceeded(string $type, int $maxActive, int $actual): self
    {
        return new self(
            sprintf(
                'Enrolling this %s credential would leave %d active, but at most %d is allowed. '
                . 'Nothing was written. Disable the existing credential in the same operation if '
                . 'this was meant to replace it.',
                $type,
                $actual,
                $maxActive,
            ),
            EnrollmentRefusalReason::CapacityExceeded,
        );
    }

    public static function contended(string $type, Throwable $previous): self
    {
        return new self(
            sprintf(
                'Another enrollment for this user\'s %s credential is in progress and did not '
                . 'release in time. Nothing was written; this is safe to retry.',
                $type,
            ),
            EnrollmentRefusalReason::Contended,
            $previous,
        );
    }
}
