<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use DateTimeImmutable;
use DateTimeInterface;
use Exception;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Expression;
use InvalidArgumentException;
use RuntimeException;

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
            // The package's timestamp columns are declared at second
            // precision. PostgreSQL otherwise compares a rounded stored value
            // with a microsecond CURRENT_TIMESTAMP, making a deadline written
            // as "now" briefly appear to be in the future.
            'pgsql' => "CURRENT_TIMESTAMP(0) + (? * INTERVAL '1 second')",
            // printf() keeps both signs valid. The throttle store compares a
            // stored start with "database now minus N" at exact fixed-window
            // boundaries; the former '+' || -N form produced the invalid
            // SQLite modifier '+-N seconds'. Positive callers remain
            // byte-for-byte equivalent at the value boundary.
            'sqlite' => "datetime('now', printf('%+d seconds', ?))",
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

    /** Resolve one database-clock deadline for use in a guarded model write. */
    public function deadline(int $seconds): DateTimeImmutable
    {
        if ($seconds < 1) {
            throw new InvalidArgumentException('A database deadline must be at least one second.');
        }

        $sql = 'SELECT ' . $this->deadlineSqlHere() . ' AS deadline';
        $raw = $this->connection->selectOne($sql, [$seconds]);
        $value = is_object($raw) ? ($raw->deadline ?? null) : null;

        if ($value instanceof DateTimeInterface) {
            return DateTimeImmutable::createFromInterface($value);
        }

        if (is_string($value)) {
            try {
                return new DateTimeImmutable($value);
            } catch (Exception) {
                // Fall through to the one fail-closed diagnostic below.
            }
        }

        throw new RuntimeException('The database returned an invalid deadline value.');
    }

    /** @return literal-string */
    public function windowStartedAtAtOrBeforeDeadlineSql(): string
    {
        return self::deadlinePredicateSql(
            $this->connection->getDriverName(),
            'window_started_at_at_or_before',
        );
    }

    /** @return literal-string */
    public function windowStartedAtAfterDeadlineSql(): string
    {
        return self::deadlinePredicateSql(
            $this->connection->getDriverName(),
            'window_started_at_after',
        );
    }

    /** @return literal-string */
    public function lockedUntilAfterDeadlineSql(): string
    {
        return self::deadlinePredicateSql(
            $this->connection->getDriverName(),
            'locked_until_after',
        );
    }

    /** @return literal-string */
    public function createdAtAfterDeadlineSql(): string
    {
        return self::deadlinePredicateSql(
            $this->connection->getDriverName(),
            'created_at_after',
        );
    }

    /** @return literal-string */
    public function dispatchedAtAtOrBeforeDeadlineSql(): string
    {
        return self::deadlinePredicateSql(
            $this->connection->getDriverName(),
            'dispatched_at_at_or_before',
        );
    }

    /**
     * Whitelisted predicates retain PHPStan's literal-string guarantee while
     * still binding the interval. Constructing `column . deadlineSql()` at a
     * call site loses that guarantee and invites future dynamic SQL into a
     * security comparison.
     *
     * @param 'window_started_at_at_or_before'|'window_started_at_after'|'locked_until_after'|'created_at_after'|'dispatched_at_at_or_before' $predicate
     * @return literal-string
     */
    private static function deadlinePredicateSql(string $driver, string $predicate): string
    {
        return match ($predicate . ':' . $driver) {
            'window_started_at_at_or_before:mysql',
            'window_started_at_at_or_before:mariadb' =>
                'window_started_at <= DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? SECOND)',
            'window_started_at_at_or_before:pgsql' =>
                "window_started_at <= CURRENT_TIMESTAMP(0) + (? * INTERVAL '1 second')",
            'window_started_at_at_or_before:sqlite' =>
                "window_started_at <= datetime('now', printf('%+d seconds', ?))",
            'window_started_at_after:mysql',
            'window_started_at_after:mariadb' =>
                'window_started_at > DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? SECOND)',
            'window_started_at_after:pgsql' =>
                "window_started_at > CURRENT_TIMESTAMP(0) + (? * INTERVAL '1 second')",
            'window_started_at_after:sqlite' =>
                "window_started_at > datetime('now', printf('%+d seconds', ?))",
            'locked_until_after:mysql',
            'locked_until_after:mariadb' =>
                'locked_until > DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? SECOND)',
            'locked_until_after:pgsql' =>
                "locked_until > CURRENT_TIMESTAMP(0) + (? * INTERVAL '1 second')",
            'locked_until_after:sqlite' =>
                "locked_until > datetime('now', printf('%+d seconds', ?))",
            'created_at_after:mysql',
            'created_at_after:mariadb' =>
                'created_at > DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? SECOND)',
            'created_at_after:pgsql' =>
                "created_at > CURRENT_TIMESTAMP(0) + (? * INTERVAL '1 second')",
            'created_at_after:sqlite' =>
                "created_at > datetime('now', printf('%+d seconds', ?))",
            'dispatched_at_at_or_before:mysql',
            'dispatched_at_at_or_before:mariadb' =>
                'dispatched_at <= DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? SECOND)',
            'dispatched_at_at_or_before:pgsql' =>
                "dispatched_at <= CURRENT_TIMESTAMP(0) + (? * INTERVAL '1 second')",
            'dispatched_at_at_or_before:sqlite' =>
                "dispatched_at <= datetime('now', printf('%+d seconds', ?))",
            default => throw new InvalidArgumentException(
                'Vouch cannot express database-clock predicate "' . $predicate
                . '" for driver "' . $driver . '".',
            ),
        };
    }
}
