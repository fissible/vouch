<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use BadMethodCallException;
use DateTimeImmutable;
use DateTimeInterface;
use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\LockContention;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use InvalidArgumentException;
use RuntimeException;

/**
 * Database-backed authentication throttle state.
 *
 * Scalar counters use a fixed window owned by the database clock. A subject
 * row is locked before its state is interpreted, but the count itself is never
 * read, incremented in PHP, and written back: rollover and increment are one
 * SQL UPDATE so concurrent committed failures cannot collapse into one.
 */
final readonly class DatabaseAuthThrottleStore implements AuthThrottleStore
{
    private BoundedLockWait $boundedLockWait;

    private LockContention $lockContention;

    public function __construct(
        private Connection $connection,
        private DatabaseTime $time,
        private ThrottleConfiguration $configuration,
        ?BoundedLockWait $boundedLockWait = null,
        ?LockContention $lockContention = null,
    ) {
        $this->boundedLockWait = $boundedLockWait ?? new BoundedLockWait($connection);
        $this->lockContention = $lockContention ?? new LockContention();
    }

    public function preflightIdentifier(ThrottleSubject $identifier): IdentifierThrottle
    {
        $this->requireDimension($identifier, ThrottleDimension::Identifier);

        $activeLock = $this->activeLock($identifier);

        if ($activeLock !== null) {
            return IdentifierThrottle::locked($activeLock);
        }

        // An expired lock is a complete, time-based unlock. Its old counter is
        // ignored here and rebased atomically by the next failed verification.
        if ($this->lockExists($identifier)) {
            return IdentifierThrottle::permitted($this->configuration->lockAfter);
        }

        $counter = $this->counter($identifier);

        return $counter === null
            ? IdentifierThrottle::permitted($this->configuration->lockAfter)
            : $this->identifierState($identifier, $counter);
    }

    public function preflightShared(ThrottleSubject $subject): SharedThrottle
    {
        if (in_array($subject->dimension, [
            ThrottleDimension::IpV4,
            ThrottleDimension::IpV6,
        ], true)) {
            $parent = $this->ipParent($subject);

            return $parent === null
                ? $this->emptyIpState($subject)
                : $this->ipState($subject, $parent);
        }

        $this->requireDimension(
            $subject,
            ThrottleDimension::Recovery,
            ThrottleDimension::Tenant,
            ThrottleDimension::Global,
        );

        $counter = $this->counter($subject);

        if ($counter === null || $this->windowExpired($subject)) {
            return $subject->dimension === ThrottleDimension::Recovery
                ? SharedThrottle::permitted()
                : SharedThrottle::observed();
        }

        return $this->sharedState($subject, $counter);
    }

    public function recordIdentifierFailure(ThrottleSubject $identifier): IdentifierThrottle
    {
        $this->requireDimension($identifier, ThrottleDimension::Identifier);
        // Read before opening the transaction. On InnoDB's default REPEATABLE
        // READ isolation, doing this read inside the transaction fixes a stale
        // snapshot before a concurrent writer releases the row lock.
        $counterExists = $this->counter($identifier) !== null;

        return $this->connection->transaction(function () use ($identifier, $counterExists): IdentifierThrottle {
            $this->ensureCounter($identifier, $counterExists);
            $counter = $this->counter($identifier, lock: true);

            if ($counter === null) {
                // Full-auth reset may delete the row after the optimistic
                // existence read but before this lock. Recreate under the same
                // transaction rather than turning a benign success/failure
                // race into a request-triggerable 500.
                $this->insertCounterIfMissing($identifier);
                $counter = $this->counter($identifier, lock: true);
            }

            if ($counter === null) {
                throw new RuntimeException('The identifier throttle counter vanished after recreation.');
            }

            $lock = $this->lock($identifier, lock: true);

            if ($lock !== null && $this->lockActive($identifier)) {
                return IdentifierThrottle::locked($lock);
            }

            $unlocking = $lock !== null;

            if ($unlocking) {
                $this->deleteLock($identifier);
            } else {
                $current = $this->identifierState($identifier, $counter);

                if ($current->decision === ThrottleDecision::BackedOff) {
                    return $current;
                }
            }

            $counter = $this->incrementCounter($identifier, forceRollover: $unlocking);

            if ($counter['count'] >= $this->configuration->lockAfter) {
                return IdentifierThrottle::locked($this->writeLock($identifier));
            }

            return $this->identifierState($identifier, $counter);
        });
    }

    public function recordRecoveryFailure(ThrottleSubject $recovery): SharedThrottle
    {
        $this->requireDimension($recovery, ThrottleDimension::Recovery);

        return $this->recordScalarFailure($recovery);
    }

    public function recordIpFailure(
        ThrottleSubject $ip,
        ThrottleSubject $ipIdentifier,
    ): SharedThrottle {
        $this->requireDimension($ip, ThrottleDimension::IpV4, ThrottleDimension::IpV6);
        $this->requireDimension($ipIdentifier, ThrottleDimension::IpIdentifier);
        // This hint must come from autocommit. A transactional existence read
        // would make the marker count after FOR UPDATE use InnoDB's earlier
        // snapshot and admit two distinct subjects at the threshold.
        $parentExists = $this->ipParent($ip) !== null;

        try {
            return $this->boundedLockWait->shared(
                fn (): SharedThrottle => $this->connection->transaction(
                    function () use ($ip, $ipIdentifier, $parentExists): SharedThrottle {
                        $this->ensureIpParent($ip, $parentExists);
                        $parent = $this->ipParent($ip, lock: true);

                        if ($parent === null) {
                            throw new RuntimeException('The IP throttle parent vanished after creation.');
                        }

                        if ($this->ipWindowExpired($ip)) {
                            $this->connection->table('auth_throttle_ip_windows')
                                ->where('id', $parent['id'])
                                ->update([
                                    'window_started_at' => $this->time->now(),
                                    'updated_at' => $this->time->now(),
                                ]);

                            $parent = $this->ipParent($ip, lock: true);

                            if ($parent === null) {
                                throw new RuntimeException('The IP throttle parent vanished after rollover.');
                            }
                        }

                        $current = $this->ipState($ip, $parent);

                        if ($current->decision === ThrottleDecision::BackedOff) {
                            return $current;
                        }

                        $now = $this->time->now();

                        $this->connection->table('auth_throttle_tuples')->insertOrIgnore([[
                            'ip_window_id' => $parent['id'],
                            'window_started_at' => $parent['windowStartedAt'],
                            'tuple_digest' => $ipIdentifier->digest,
                            'created_at' => $now,
                            'updated_at' => $now,
                        ]]);

                        return $this->ipState($ip, $parent);
                    },
                ),
            );
        } catch (QueryException $exception) {
            if ($this->lockContention->isVerified($this->connection, $exception)) {
                return SharedThrottle::skipped();
            }

            throw $exception;
        }
    }

    public function recordSharedFailure(ThrottleSubject $subject): SharedThrottle
    {
        $this->requireDimension(
            $subject,
            ThrottleDimension::Tenant,
            ThrottleDimension::Global,
        );

        return $this->recordScalarFailure($subject);
    }

    public function resetIdentifier(ThrottleSubject $identifier): void
    {
        $this->requireDimension($identifier, ThrottleDimension::Identifier);

        $this->connection->transaction(function () use ($identifier): void {
            // Every writer takes the counter before the lock row. Preserve that
            // order here so successful authentication cannot deadlock a racing
            // failure by taking the two records in reverse.
            $this->counterQuery($identifier)->delete();

            $this->connection->table('auth_throttle_locks')
                ->where('subject_digest', $identifier->digest)
                ->delete();
        });
    }

    public function recordChallengeFailure(int $challengeId): ChallengeAttemptDecision
    {
        return $this->connection->transaction(function () use ($challengeId): ChallengeAttemptDecision {
            $grammar = $this->connection->getQueryGrammar();
            $table = $grammar->wrapTable('auth_challenges');
            $id = $grammar->wrap('id');
            $attempts = $grammar->wrap('attempts');
            $consumedAt = $grammar->wrap('consumed_at');
            $expiresAt = $grammar->wrap('expires_at');
            $updatedAt = $grammar->wrap('updated_at');
            $limit = $this->configuration->challengeAttempts;

            /*
             * Increment and terminal invalidation are one database operation.
             * A PHP read-increment-write lets a burst of concurrent guesses all
             * observe the same count and collapse into one; that is the exact
             * workload this boundary exists to withstand. Starting with UPDATE
             * also claims SQLite's writer lock before any state-bearing read.
             */
            $affected = $this->connection->update(
                "UPDATE {$table} SET "
                . "{$consumedAt} = CASE WHEN {$attempts} + 1 >= ? "
                . "THEN CURRENT_TIMESTAMP ELSE {$consumedAt} END, "
                // MySQL evaluates assignments left-to-right. Keep the CASE
                // before the increment so every engine tests the OLD count;
                // reversing these two makes MySQL invalidate at four.
                . "{$attempts} = {$attempts} + 1, "
                . "{$updatedAt} = CURRENT_TIMESTAMP "
                . "WHERE {$id} = ? AND {$consumedAt} IS NULL "
                . "AND {$expiresAt} > CURRENT_TIMESTAMP AND {$attempts} < ?",
                [$limit, $challengeId, $limit],
            );

            if ($affected === 0) {
                $raw = $this->connection->table('auth_challenges')
                    ->where('id', $challengeId)
                    ->lockForUpdate()
                    ->first(['consumed_at']);

                if ($raw === null) {
                    return ChallengeAttemptDecision::Unavailable;
                }

                $row = (array) $raw;

                if (($row['consumed_at'] ?? null) !== null) {
                    return ChallengeAttemptDecision::Consumed;
                }

                $expired = $this->connection->table('auth_challenges')
                    ->where('id', $challengeId)
                    ->where('expires_at', '<=', $this->time->now())
                    ->exists();

                return $expired
                    ? ChallengeAttemptDecision::Expired
                    : ChallengeAttemptDecision::Unavailable;
            }

            if ($affected !== 1) {
                throw new RuntimeException(
                    'The challenge-attempt update did not affect exactly one row.',
                );
            }

            $raw = $this->connection->table('auth_challenges')
                ->where('id', $challengeId)
                ->lockForUpdate()
                ->first(['attempts', 'consumed_at']);

            if ($raw === null) {
                throw new RuntimeException('The challenge vanished after its atomic attempt update.');
            }

            $row = (array) $raw;
            $count = $row['attempts'] ?? null;

            if (! is_int($count) || $count < 1 || $count > $limit) {
                throw new RuntimeException('The database returned an invalid challenge-attempt count.');
            }

            return $row['consumed_at'] === null
                ? ChallengeAttemptDecision::Remaining
                : ChallengeAttemptDecision::Invalidated;
        });
    }

    public function permitIssuance(ThrottleSubject $issuance): IssuancePermission
    {
        throw new BadMethodCallException('Challenge-issuance permission is implemented in Task 14.');
    }

    private function recordScalarFailure(ThrottleSubject $subject): SharedThrottle
    {
        // Keep the existence hint outside the transaction for the same InnoDB
        // snapshot reason as the authoritative identifier counter.
        $counterExists = $this->counter($subject) !== null;

        return $this->connection->transaction(function () use ($subject, $counterExists): SharedThrottle {
            $this->ensureCounter($subject, $counterExists);
            $counter = $this->counter($subject, lock: true);

            if ($counter === null) {
                $this->insertCounterIfMissing($subject);
                $counter = $this->counter($subject, lock: true);
            }

            if ($counter === null) {
                throw new RuntimeException('The shared throttle counter vanished after recreation.');
            }

            $current = $this->sharedState($subject, $counter);

            if ($current->decision === ThrottleDecision::BackedOff) {
                return $current;
            }

            return $this->sharedState($subject, $this->incrementCounter($subject));
        });
    }

    private function ensureIpParent(ThrottleSubject $ip, bool $existedBeforeTransaction): void
    {
        if ($this->connection->getDriverName() === 'sqlite') {
            $this->insertIpParentIfMissing($ip);

            return;
        }

        if ($existedBeforeTransaction) {
            return;
        }

        $this->insertIpParentIfMissing($ip);
    }

    private function insertIpParentIfMissing(ThrottleSubject $ip): void
    {
        $now = $this->time->now();

        $this->connection->table('auth_throttle_ip_windows')->insertOrIgnore([[
            'dimension' => $ip->dimension->value,
            'ip_digest' => $ip->digest,
            'window_started_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]]);
    }

    /** @return array{id: int, windowStartedAt: DateTimeImmutable}|null */
    private function ipParent(ThrottleSubject $ip, bool $lock = false): ?array
    {
        $query = $this->ipParentQuery($ip);

        if ($lock) {
            $query->lockForUpdate();
        }

        $raw = $query->first(['id', 'window_started_at']);

        if ($raw === null) {
            return null;
        }

        $row = (array) $raw;
        $id = $row['id'] ?? null;

        if (! is_int($id) || $id < 1) {
            throw new RuntimeException('The database returned an invalid IP throttle parent id.');
        }

        return [
            'id' => $id,
            'windowStartedAt' => $this->date($row['window_started_at'] ?? null),
        ];
    }

    private function ipParentQuery(ThrottleSubject $ip): Builder
    {
        return $this->connection->table('auth_throttle_ip_windows')
            ->where('dimension', $ip->dimension->value)
            ->where('ip_digest', $ip->digest);
    }

    private function ipWindowExpired(ThrottleSubject $ip): bool
    {
        return $this->ipParentQuery($ip)
            ->whereRaw(
                $this->time->windowStartedAtAtOrBeforeDeadlineSql(),
                [-$this->configuration->windowSeconds],
            )
            ->exists();
    }

    /**
     * @param array{id: int, windowStartedAt: DateTimeImmutable} $parent
     */
    private function ipState(ThrottleSubject $ip, array $parent): SharedThrottle
    {
        if ($this->ipWindowExpired($ip)) {
            return $this->emptyIpState($ip);
        }

        if ($this->configuration->ipMode === 'observe') {
            return SharedThrottle::observed();
        }

        $threshold = $ip->dimension === ThrottleDimension::IpV4
            ? $this->configuration->ipv4EnforceAt
            : $this->configuration->ipv6EnforceAt;
        $backoff = $this->configuration->ipBackoffSeconds;

        if ($threshold === null || $backoff === null) {
            throw new RuntimeException('Validated IP enforcement configuration is incomplete.');
        }

        $markers = $this->tupleQuery($parent)->count();

        if ($markers < $threshold) {
            return SharedThrottle::permitted();
        }

        $latest = $this->tupleQuery($parent)
            ->whereRaw($this->time->createdAtAfterDeadlineSql(), [-$backoff])
            ->max('created_at');

        if ($latest === null) {
            return SharedThrottle::permitted();
        }

        $retryAfter = $this->date($latest)->modify('+' . $backoff . ' seconds');
        $windowDeadline = $parent['windowStartedAt']
            ->modify('+' . $this->configuration->windowSeconds . ' seconds');

        return SharedThrottle::backedOff(
            $retryAfter > $windowDeadline ? $windowDeadline : $retryAfter,
        );
    }

    private function emptyIpState(ThrottleSubject $ip): SharedThrottle
    {
        return $this->configuration->ipMode === 'observe'
            ? SharedThrottle::observed()
            : SharedThrottle::permitted();
    }

    /**
     * @param array{id: int, windowStartedAt: DateTimeImmutable} $parent
     */
    private function tupleQuery(array $parent): Builder
    {
        return $this->connection->table('auth_throttle_tuples')
            ->where('ip_window_id', $parent['id'])
            ->where('window_started_at', $parent['windowStartedAt']);
    }

    /**
     * @param array{count: int, windowStartedAt: DateTimeImmutable} $counter
     */
    private function identifierState(
        ThrottleSubject $identifier,
        array $counter,
    ): IdentifierThrottle {
        if ($this->windowExpired($identifier)) {
            return IdentifierThrottle::permitted($this->configuration->lockAfter);
        }

        if ($counter['count'] >= $this->configuration->lockAfter) {
            throw new RuntimeException(
                'An identifier counter reached its lock threshold without a lock record.',
            );
        }

        $remaining = $this->configuration->lockAfter - $counter['count'];

        if ($counter['count'] < $this->configuration->backoffAfter) {
            return IdentifierThrottle::permitted($remaining);
        }

        $offset = $this->backoffOffset($counter['count']);

        if (! $this->deadlinePending($identifier, $offset)) {
            return IdentifierThrottle::permitted($remaining);
        }

        return IdentifierThrottle::backedOff(
            $remaining,
            $this->deadline($counter['windowStartedAt'], $offset),
        );
    }

    /**
     * @param array{count: int, windowStartedAt: DateTimeImmutable} $counter
     */
    private function sharedState(ThrottleSubject $subject, array $counter): SharedThrottle
    {
        if ($this->windowExpired($subject)) {
            return $subject->dimension === ThrottleDimension::Recovery
                ? SharedThrottle::permitted()
                : SharedThrottle::observed();
        }

        if ($subject->dimension !== ThrottleDimension::Recovery) {
            // Tenant and global ship unarmed. Their live counters support the
            // aggregate report; Task 12 adds their explicitly configured
            // enforcement decision at the integration boundary.
            return SharedThrottle::observed();
        }

        if ($counter['count'] < $this->configuration->backoffAfter) {
            return SharedThrottle::permitted();
        }

        $offset = $this->backoffOffset($counter['count']);

        return $this->deadlinePending($subject, $offset)
            ? SharedThrottle::backedOff($this->deadline($counter['windowStartedAt'], $offset))
            : SharedThrottle::permitted();
    }

    private function backoffOffset(int $count): int
    {
        $offset = 0;
        $delay = $this->configuration->initialBackoffSeconds;
        $step = $this->configuration->backoffAfter;

        while ($step <= $count && $offset < $this->configuration->windowSeconds) {
            $offset += min($delay, $this->configuration->backoffCapSeconds);
            $offset = min($offset, $this->configuration->windowSeconds);

            if ($delay < $this->configuration->backoffCapSeconds) {
                $delay = min(
                    $this->configuration->backoffCapSeconds,
                    $delay * $this->configuration->backoffBase,
                );
            }

            $step++;
        }

        return $offset;
    }

    private function deadline(DateTimeImmutable $windowStartedAt, int $offset): DateTimeImmutable
    {
        return $windowStartedAt->modify('+' . min($offset, $this->configuration->windowSeconds) . ' seconds');
    }

    private function ensureCounter(ThrottleSubject $subject, bool $existedBeforeTransaction): void
    {
        if ($this->connection->getDriverName() === 'sqlite') {
            // SQLite's FOR UPDATE is a bare SELECT. Make the unique insert the
            // first statement so the transaction claims the global writer
            // lock before any state-bearing read. A read-then-write upgrade
            // cannot wait safely while another writer is trying to commit.
            $this->insertCounterIfMissing($subject);

            return;
        }

        // Do not issue INSERT IGNORE against a row that already exists. On
        // MySQL that duplicate-key path takes a shared record lock; two writers
        // can then deadlock when both try to upgrade it through FOR UPDATE.
        // The absent-row path still uses the unique insert as its serializer.
        if ($existedBeforeTransaction) {
            return;
        }

        $this->insertCounterIfMissing($subject);
    }

    private function insertCounterIfMissing(ThrottleSubject $subject): void
    {
        $now = $this->time->now();

        $this->connection->table('auth_throttle_counters')->insertOrIgnore([[
            'dimension' => $subject->dimension->value,
            'subject_digest' => $subject->digest,
            'window_started_at' => $now,
            'count' => 0,
            'created_at' => $now,
            'updated_at' => $now,
        ]]);
    }

    /** @return array{count: int, windowStartedAt: DateTimeImmutable} */
    private function incrementCounter(
        ThrottleSubject $subject,
        bool $forceRollover = false,
    ): array {
        $grammar = $this->connection->getQueryGrammar();
        $table = $grammar->wrapTable('auth_throttle_counters');
        $count = $grammar->wrap('count');
        $window = $grammar->wrap('window_started_at');
        $updated = $grammar->wrap('updated_at');
        $dimension = $grammar->wrap('dimension');
        $digest = $grammar->wrap('subject_digest');
        $deadline = $this->time->deadlineSqlHere();
        $expired = "{$window} <= {$deadline}";

        $affected = $this->connection->update(
            "UPDATE {$table} SET "
            . "{$count} = CASE WHEN ? = 1 OR {$expired} THEN 1 ELSE {$count} + 1 END, "
            . "{$window} = CASE WHEN ? = 1 OR {$expired} THEN CURRENT_TIMESTAMP ELSE {$window} END, "
            . "{$updated} = CURRENT_TIMESTAMP "
            . "WHERE {$dimension} = ? AND {$digest} = ?",
            [
                $forceRollover ? 1 : 0,
                -$this->configuration->windowSeconds,
                $forceRollover ? 1 : 0,
                -$this->configuration->windowSeconds,
                $subject->dimension->value,
                $subject->digest,
            ],
        );

        if ($affected !== 1) {
            throw new RuntimeException('The throttle counter update did not affect exactly one row.');
        }

        $counter = $this->counter($subject, lock: true);

        if ($counter === null) {
            throw new RuntimeException('The throttle counter vanished after its atomic update.');
        }

        return $counter;
    }

    /** @return array{count: int, windowStartedAt: DateTimeImmutable}|null */
    private function counter(ThrottleSubject $subject, bool $lock = false): ?array
    {
        $query = $this->counterQuery($subject);

        if ($lock) {
            $query->lockForUpdate();
        }

        $raw = $query->first(['count', 'window_started_at']);

        if ($raw === null) {
            return null;
        }

        $row = (array) $raw;
        $count = $row['count'] ?? null;

        if (! is_int($count) || $count < 0) {
            throw new RuntimeException('The database returned an invalid throttle count.');
        }

        return [
            'count' => $count,
            'windowStartedAt' => $this->date($row['window_started_at'] ?? null),
        ];
    }

    private function counterQuery(ThrottleSubject $subject): \Illuminate\Database\Query\Builder
    {
        return $this->connection->table('auth_throttle_counters')
            ->where('dimension', $subject->dimension->value)
            ->where('subject_digest', $subject->digest);
    }

    private function windowExpired(ThrottleSubject $subject): bool
    {
        return $this->counterQuery($subject)
            ->whereRaw(
                $this->time->windowStartedAtAtOrBeforeDeadlineSql(),
                [-$this->configuration->windowSeconds],
            )
            ->exists();
    }

    private function deadlinePending(ThrottleSubject $subject, int $offset): bool
    {
        return $this->counterQuery($subject)
            ->whereRaw($this->time->windowStartedAtAfterDeadlineSql(), [-$offset])
            ->exists();
    }

    private function writeLock(ThrottleSubject $identifier): DateTimeImmutable
    {
        $now = $this->time->now();

        $this->connection->table('auth_throttle_locks')->insertOrIgnore([[
            'subject_digest' => $identifier->digest,
            'locked_until' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]]);

        $grammar = $this->connection->getQueryGrammar();
        $table = $grammar->wrapTable('auth_throttle_locks');
        $deadline = $grammar->wrap('locked_until');
        $updated = $grammar->wrap('updated_at');
        $digest = $grammar->wrap('subject_digest');

        $affected = $this->connection->update(
            "UPDATE {$table} SET {$deadline} = {$this->time->deadlineSqlHere()}, "
            . "{$updated} = CURRENT_TIMESTAMP WHERE {$digest} = ?",
            [$this->configuration->lockDurationSeconds, $identifier->digest],
        );

        if ($affected !== 1) {
            throw new RuntimeException('The throttle lock write did not affect exactly one row.');
        }

        $lock = $this->lock($identifier, lock: true);

        if ($lock === null) {
            throw new RuntimeException('The throttle lock vanished after creation.');
        }

        return $lock;
    }

    private function activeLock(ThrottleSubject $identifier): ?DateTimeImmutable
    {
        $raw = $this->connection->table('auth_throttle_locks')
            ->where('subject_digest', $identifier->digest)
            ->whereRaw($this->time->lockedUntilAfterDeadlineSql(), [0])
            ->value('locked_until');

        return $raw === null ? null : $this->date($raw);
    }

    private function lock(ThrottleSubject $identifier, bool $lock = false): ?DateTimeImmutable
    {
        $query = $this->connection->table('auth_throttle_locks')
            ->where('subject_digest', $identifier->digest);

        if ($lock) {
            $query->lockForUpdate();
        }

        $raw = $query->value('locked_until');

        return $raw === null ? null : $this->date($raw);
    }

    private function lockActive(ThrottleSubject $identifier): bool
    {
        return $this->connection->table('auth_throttle_locks')
            ->where('subject_digest', $identifier->digest)
            ->whereRaw($this->time->lockedUntilAfterDeadlineSql(), [0])
            ->exists();
    }

    private function lockExists(ThrottleSubject $identifier): bool
    {
        return $this->connection->table('auth_throttle_locks')
            ->where('subject_digest', $identifier->digest)
            ->exists();
    }

    private function deleteLock(ThrottleSubject $identifier): void
    {
        $this->connection->table('auth_throttle_locks')
            ->where('subject_digest', $identifier->digest)
            ->delete();
    }

    private function date(mixed $value): DateTimeImmutable
    {
        if ($value instanceof DateTimeInterface) {
            return DateTimeImmutable::createFromInterface($value);
        }

        if (is_string($value)) {
            return new DateTimeImmutable($value);
        }

        throw new RuntimeException('The database returned an invalid throttle timestamp.');
    }

    private function requireDimension(
        ThrottleSubject $subject,
        ThrottleDimension ...$allowed,
    ): void {
        if (! in_array($subject->dimension, $allowed, true)) {
            throw new InvalidArgumentException(sprintf(
                'Throttle operation does not accept dimension "%s".',
                $subject->dimension->value,
            ));
        }
    }
}
