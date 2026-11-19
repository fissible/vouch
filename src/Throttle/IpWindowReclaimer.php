<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use Fissible\Vouch\Support\DatabaseRowLock;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\DurationBounds;
use Fissible\Vouch\Support\IpThrottleLockBucket;
use Illuminate\Database\Connection;
use RuntimeException;

/**
 * #16. Deletes expired IP throttle windows, each under its own lock bucket.
 *
 * One short transaction per window rather than one for the sweep: a sweep
 * holding thousands of buckets would block logins for its whole length. Under
 * the bucket, the delete rechecks the same database-clock predicate the throttle
 * reads, so a window renewed while prune waited survives. Tuples cascade.
 *
 * Expired windows carry no live state -- the throttle reads an expired window
 * as empty -- and the throttle report counts only active ones, so reclaiming
 * them changes no decision and no report.
 */
final readonly class IpWindowReclaimer
{
    private const BATCH = 500;

    private const TABLE = 'auth_throttle_ip_windows';

    public function __construct(
        private Connection $connection,
        private DatabaseTime $time,
        private ThrottleConfiguration $configuration,
    ) {}

    public function reclaim(): int
    {
        $offset = -DurationBounds::backward(
            $this->configuration->windowSeconds,
            'vouch.throttle.window_seconds',
            $this->time->current(),
        );
        $predicate = $this->time->windowStartedAtAtOrBeforeDeadlineSql();
        $reclaimed = 0;
        $after = 0;

        do {
            $candidates = $this->connection->table(self::TABLE)
                ->where('id', '>', $after)
                ->whereRaw($predicate, [$offset])
                ->orderBy('id')
                ->limit(self::BATCH)
                ->get(['id', 'dimension', 'ip_digest']);

            foreach ($candidates as $candidate) {
                $row = (array) $candidate;
                $id = $row['id'] ?? null;
                $dimension = $row['dimension'] ?? null;
                $digest = $row['ip_digest'] ?? null;

                if (! is_int($id) || ! is_string($dimension) || ! is_string($digest)) {
                    throw new RuntimeException('The database returned an unreadable IP throttle window.');
                }

                $after = $id;
                $reclaimed += $this->reclaimOne($id, $dimension, $digest, $predicate, $offset);
            }
        } while ($candidates->count() === self::BATCH);

        return $reclaimed;
    }

    /** @param literal-string $predicate */
    private function reclaimOne(int $id, string $dimension, string $digest, string $predicate, int $offset): int
    {
        return $this->connection->transaction(function () use ($id, $dimension, $digest, $predicate, $offset): int {
            /*
             * Not on SQLite: the database write lock already serializes, and a
             * leading read there turns a concurrent login's write into an
             * immediate SQLITE_BUSY on lock upgrade.
             */
            if ($this->connection->getDriverName() !== 'sqlite') {
                (new DatabaseRowLock($this->connection))->lockBuckets(
                    IpThrottleLockBucket::TABLE,
                    IpThrottleLockBucket::buckets($dimension, $digest),
                );
            }

            return $this->connection->table(self::TABLE)
                ->where('id', $id)
                ->whereRaw($predicate, [$offset])
                ->delete();
        });
    }
}
