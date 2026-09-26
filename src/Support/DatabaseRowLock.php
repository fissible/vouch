<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Illuminate\Database\ConnectionInterface;
use RuntimeException;

/**
 * Shared serialization-row primitives: lock a pre-seeded row, or ensure then lock.
 *
 * `ensureAndLock`'s insert is intentionally `insertOrIgnore`, followed by a
 * separate `FOR UPDATE` read. Engines differ on which statement serializes an
 * existing row; callers must still matrix-test the committed-row path.
 */
final readonly class DatabaseRowLock
{
    public function __construct(private ConnectionInterface $connection) {}

    /**
     * Lock one pre-seeded mutex row, and refuse rather than create.
     *
     * #46: the bucket rows come from the migration, so a missing one is a broken
     * installation rather than something to insert -- and inserting here is
     * precisely the unbounded growth the bucketing removes.
     *
     * Exclusive rather than shared, and taken before the write it protects.
     * Measured: a shared lock, no lock at all, and a lock taken after the
     * supersession write are all indistinguishable on SQLite, which locks the
     * whole database for any write, and all three fail on PostgreSQL.
     */
    public function lockBucket(string $table, int $bucket): void
    {
        $row = $this->connection->table($table)
            ->where('bucket', $bucket)
            ->lockForUpdate()
            ->first();

        if ($row === null) {
            throw new RuntimeException(sprintf(
                'The mutex bucket %d is not seeded in %s.',
                $bucket,
                $table,
            ));
        }
    }

    /**
     * @param array<string, mixed> $insert
     * @param array<string, scalar|null> $where
     */
    public function ensureAndLock(string $table, array $insert, array $where): void
    {
        $this->connection->table($table)->insertOrIgnore([$insert]);

        $query = $this->connection->table($table);

        foreach ($where as $column => $value) {
            $query->where($column, $value);
        }

        if ($query->lockForUpdate()->first() === null) {
            throw new RuntimeException(sprintf(
                'The serialization row vanished from %s after ensure.',
                $table,
            ));
        }
    }
}
