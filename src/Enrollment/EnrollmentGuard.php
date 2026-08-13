<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;

/**
 * Serializes credential enrollment per (user_id, type) and enforces cardinality.
 *
 * maxActiveCredentials() is a property on a driver; it becomes an invariant only
 * when the write path is atomic. Count-then-insert is a read-modify-write, so
 * two concurrent enrollments each observe capacity and each proceed: two active
 * passwords, two TOTP secrets, or twenty recovery codes from two interleaved
 * regenerations.
 *
 * Row locks alone cannot fix it. SELECT ... FOR UPDATE over auth_credentials
 * locks the rows that exist, and the first-enrollment race is precisely the case
 * where there are none. Hence a dedicated lock row that always exists before the
 * count is taken.
 */
final class EnrollmentGuard
{
    /**
     * Typed against the concrete Connection, not ConnectionInterface: the
     * per-driver dispatch in boundTheWait() and isLockContention() needs
     * getDriverName(), which the interface does not declare. DB::connection()
     * already returns Connection, so this costs callers nothing.
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly int $lockWaitSeconds = 5,
    ) {}

    /**
     * Run $write with exclusive access to this user's credentials of this type,
     * refusing if the result would exceed $maxActive.
     *
     * The cardinality check is a POST-condition. A pre-check would refuse
     * password change and OTP re-enrollment, which disable a row and create one
     * inside the same closure; the post-check accepts those and still catches
     * the double-enroll. One code path, and it is the stronger one.
     *
     * @template TResult
     *
     * @param  int|null  $maxActive  Null means unbounded — skip the check entirely.
     * @param  callable(): TResult  $write
     * @return TResult
     *
     * @throws EnrollmentRefused
     */
    public function serialize(int $userId, string $type, ?int $maxActive, callable $write): mixed
    {
        return $this->connection->transaction(function () use ($userId, $type, $maxActive, $write): mixed {
            $this->acquire($userId, $type);

            $result = $write();

            if ($maxActive !== null) {
                $active = $this->countActive($userId, $type);

                if ($active > $maxActive) {
                    // Throwing rolls the whole closure back, so a partially
                    // applied enrollment cannot survive the refusal.
                    throw EnrollmentRefused::capacityExceeded($type, $maxActive, $active);
                }
            }

            return $result;
        });
    }

    /**
     * Claim and lock this subject's row.
     *
     * insertOrIgnore, NOT upsert with an empty update array: the latter compiles
     * to a plain INSERT on every engine and throws a unique violation the second
     * time. Verified on SQLite, MySQL 8 and Postgres 16.
     *
     * On MySQL and Postgres the lockForUpdate is what serializes. On SQLite it
     * compiles to a bare SELECT and does nothing — serialization there comes
     * from the database-level write lock that insertOrIgnore already took. Same
     * outcome, different mechanism; both are exercised by the contention matrix.
     *
     * @throws EnrollmentRefused
     */
    private function acquire(int $userId, string $type): void
    {
        try {
            $this->boundTheWait();

            $this->connection->table('auth_enrollment_locks')
                ->insertOrIgnore([['user_id' => $userId, 'type' => $type]]);

            $this->connection->table('auth_enrollment_locks')
                ->where('user_id', $userId)
                ->where('type', $type)
                ->lockForUpdate()
                ->first();
        } catch (QueryException $exception) {
            /*
             * ONLY verified lock/busy codes map to a refusal. A blanket
             * catch would report a dropped table, a rejected session setting, or
             * any future query defect as ordinary contention — and
             * EnrollmentRefused::contended() tells the caller it is "safe to
             * retry", which is precisely the wrong advice for a schema problem.
             * Everything else rethrows unchanged.
             */
            if (! $this->isLockContention($exception)) {
                throw $exception;
            }

            throw EnrollmentRefused::contended($type, $exception);
        }
    }

    /**
     * Is this exception a lock-wait timeout or a busy database?
     *
     * SQLSTATE alone cannot answer this. MySQL and SQLite both report contention
     * as HY000 — the general-error catch-all — and on SQLite a missing table is
     * ALSO HY000. So the driver-specific code is the discriminator on those two,
     * and the SQLSTATE is the discriminator on Postgres, which is the only engine
     * that gives contention its own.
     *
     * Measured against MySQL 8, Postgres 16 and SQLite:
     *
     *   contention     mysql HY000/1205   pgsql 55P03/7   sqlite HY000/5
     *   missing table  mysql 42S02/1146   pgsql 42P01/7   sqlite HY000/1
     *   bad column     mysql 42S22/1054   pgsql 42703/7   sqlite HY000/1
     *
     * Deadlock siblings — MySQL 1213, Postgres 40P01/40001, SQLite 6
     * (SQLITE_LOCKED) — are deliberately NOT matched. They are plausibly
     * retryable too, but they were not observed in the probe, and widening an
     * error mask on reasoning rather than measurement is the mistake this method
     * exists to correct. A deadlock therefore surfaces as a QueryException,
     * which is honest.
     *
     * An unrecognised driver returns false, so an unknown engine fails loudly
     * rather than silently classifying every error as contention.
     */
    private function isLockContention(QueryException $exception): bool
    {
        $driverCode = $exception->errorInfo[1] ?? null;

        return match ($this->connection->getDriverName()) {
            'mysql' => $driverCode === 1205,
            'pgsql' => $exception->getCode() === '55P03',
            'sqlite' => $driverCode === 5,
            default => false,
        };
    }

    /**
     * Bound the lock wait, because the engine defaults are wildly inconsistent:
     * MySQL waits 50 seconds, Postgres waits forever, SQLite fails immediately.
     * An unbounded wait hangs a request thread on a contended enrollment.
     *
     * KNOWN SIDE EFFECT — the scope is not uniform across the three engines, and
     * on two of them it OUTLIVES the enrollment. Only Postgres's SET LOCAL is
     * transaction-scoped and reverts on commit. MySQL's SET SESSION and SQLite's
     * PRAGMA busy_timeout persist for the life of the CONNECTION, so under a
     * long-lived worker — Octane, a pooled connection, queue workers, anything
     * that does not tear the connection down per request — one enrollment leaves
     * the host application's lock timeout at vouch.enrollment.lock_wait_seconds
     * for every later query on that connection, including queries that have
     * nothing to do with vouch. Since the value is a bound (default 5s) rather
     * than an extension, the practical effect is a LOWERED tolerance: a host that
     * relied on MySQL's 50-second default will start seeing lock-wait timeouts on
     * its own contended writes after any enrollment runs on that connection.
     * Restoring the prior value would mean reading it back and resetting it on
     * every path out — including the throwing ones — which is its own correctness
     * problem; it is documented rather than done.
     */
    private function boundTheWait(): void
    {
        $seconds = max(1, $this->lockWaitSeconds);

        match ($this->connection->getDriverName()) {
            // SET LOCAL is scoped to this transaction and reverts on commit.
            'pgsql' => $this->connection->statement(sprintf("SET LOCAL lock_timeout = '%ds'", $seconds)),
            'mysql' => $this->connection->statement(sprintf('SET SESSION innodb_lock_wait_timeout = %d', $seconds)),
            'sqlite' => $this->connection->statement(sprintf('PRAGMA busy_timeout = %d', $seconds * 1000)),
            default => null,
        };
    }

    private function countActive(int $userId, string $type): int
    {
        return $this->connection->table('auth_credentials')
            ->where('user_id', $userId)
            ->where('type', $type)
            ->whereNull('disabled_at')
            ->count();
    }
}
