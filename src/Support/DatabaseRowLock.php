<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Illuminate\Database\Connection;
use RuntimeException;

/**
 * Shared ensure-then-lock primitive for serialization rows.
 *
 * The insert is intentionally `insertOrIgnore`, followed by a separate
 * `FOR UPDATE` read. Engines differ on which statement serializes an existing
 * row; callers must still matrix-test the committed-row path.
 */
final readonly class DatabaseRowLock
{
    public function __construct(private Connection $connection) {}

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
