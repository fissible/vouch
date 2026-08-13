<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Expression;
use InvalidArgumentException;

/**
 * The database's own clock, for values that are also read in database time.
 *
 * A security window written from the application clock but evaluated against
 * CURRENT_TIMESTAMP is nominally fifteen minutes and actually fifteen minutes
 * plus or minus whatever drift exists between two machines. Recovery grace is a
 * security boundary, so both halves use one authority.
 *
 * This is the same seam documented on DatabaseAttemptStore::now(), and the one
 * that silently invalidated Phase 2.2's TOTP tests — green only while real time
 * happened to sit before a frozen expiry.
 *
 * Interval arithmetic is not portable, so the expression is built once here
 * rather than at each call site. An unrecognised driver THROWS: falling back to
 * an application timestamp would reintroduce the drift this class exists to
 * remove, silently, on whichever engine nobody tested.
 */
final readonly class DatabaseTime
{
    public function __construct(private Connection $connection) {}

    /** @return Expression<'CURRENT_TIMESTAMP'> */
    public function now(): Expression
    {
        return new Expression('CURRENT_TIMESTAMP');
    }

    /**
     * SQL for a deadline N seconds from the database's current time, with N as
     * a BOUND PARAMETER rather than interpolated.
     *
     * Every branch is a true literal, which is both the safe form and the only
     * form the type system can vouch for: interpolating even a provably-safe
     * int yields a non-literal string that Expression cannot accept. Callers
     * bind the seconds.
     *
     * An unrecognised driver THROWS. Falling back to an application timestamp
     * would reintroduce the drift this class exists to remove — silently, on
     * whichever engine nobody tested.
     *
     * @return literal-string
     */
    public static function deadlineSql(string $driver): string
    {
        return match ($driver) {
            'mysql', 'mariadb' => 'DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? SECOND)',
            'pgsql' => "CURRENT_TIMESTAMP + (? * INTERVAL '1 second')",
            'sqlite' => "datetime('now', '+' || ? || ' seconds')",
            default => throw new InvalidArgumentException(
                'Vouch cannot express a database-clock deadline for driver "' . $driver . '". '
                . 'Add the interval expression for it rather than falling back to an '
                . 'application timestamp: that would reintroduce clock drift into a security '
                . 'window, silently, on the one engine nobody tested.',
            ),
        };
    }

    /** SQL for a deadline on THIS connection's driver. @return literal-string */
    public function deadlineSqlHere(): string
    {
        return self::deadlineSql($this->connection->getDriverName());
    }
}
