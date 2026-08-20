<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Support\DatabaseRowLock;
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
     * bounded-wait and contention collaborators need driver identity, which the
     * interface does not declare. DB::connection() already returns Connection,
     * so this costs callers nothing.
     */
    private readonly BoundedLockWait $boundedLockWait;

    private readonly LockContention $lockContention;

    private readonly DatabaseRowLock $rowLock;

    public function __construct(
        private readonly Connection $connection,
        private readonly int $lockWaitSeconds = 5,
        ?BoundedLockWait $boundedLockWait = null,
        ?LockContention $lockContention = null,
        ?DatabaseRowLock $rowLock = null,
    ) {
        $this->boundedLockWait = $boundedLockWait ?? new BoundedLockWait($connection);
        $this->lockContention = $lockContention ?? new LockContention();
        $this->rowLock = $rowLock ?? new DatabaseRowLock($connection);
    }

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
     * Which of these two statements serializes depends on the engine AND on
     * whether the lock row already exists. Measured on all three:
     *
     * - First enrollment for a subject (no row yet): the insert serializes on
     *   every engine. The second writer blocks on the duplicate key and is
     *   refused before it ever reaches the select.
     * - Every later enrollment (row committed, and nothing ever deletes from
     *   this table): insertOrIgnore is a no-op. On Postgres it takes no lock at
     *   all, so lockForUpdate is the ONLY thing serializing — remove it and two
     *   writers both win. On MySQL InnoDB still takes a shared lock on the
     *   conflicting index record, which blocks against the holder's exclusive
     *   lock, so the insert covers it there too. On SQLite lockForUpdate
     *   compiles to a bare SELECT and does nothing; the database-level write
     *   lock does the work.
     *
     * So the call is load-bearing on Postgres re-enrollment specifically, and
     * redundant-but-harmless elsewhere. Removing it is only observable on
     * Postgres, which is what the re-enrollment contention test pins.
     *
     * @throws EnrollmentRefused
     */
    private function acquire(int $userId, string $type): void
    {
        try {
            $this->boundedLockWait->enrollment(max(1, $this->lockWaitSeconds), function () use ($userId, $type): void {
                $this->rowLock->ensureAndLock(
                    'auth_enrollment_locks',
                    ['user_id' => $userId, 'type' => $type],
                    ['user_id' => $userId, 'type' => $type],
                );
            });
        } catch (QueryException $exception) {
            /*
             * ONLY verified lock/busy codes map to a refusal. A blanket
             * catch would report a dropped table, a rejected session setting, or
             * any future query defect as ordinary contention — and
             * EnrollmentRefused::contended() tells the caller it is "safe to
             * retry", which is precisely the wrong advice for a schema problem.
             * Everything else rethrows unchanged.
             */
            if (! $this->lockContention->isVerified($this->connection, $exception)) {
                throw $exception;
            }

            throw EnrollmentRefused::contended($type, $exception);
        }
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
