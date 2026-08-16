<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;

/**
 * Classifies only lock contention measured on the supported database engines.
 *
 * SQLSTATE alone cannot answer this: MySQL and SQLite both report contention
 * under the HY000 general-error class, and SQLite uses that same SQLSTATE for a
 * missing table. The measured discriminators are MySQL driver code 1205,
 * PostgreSQL SQLSTATE 55P03, and SQLite driver code 5.
 *
 * Deadlock siblings (MySQL 1213, PostgreSQL 40P01/40001, SQLite 6) are not
 * included. They may be retryable, but they were not observed in the probe that
 * established this classifier. Unknown engines and unmeasured codes therefore
 * stay loud rather than being mislabeled safe to retry.
 */
final readonly class LockContention
{
    public function isVerified(Connection $connection, QueryException $exception): bool
    {
        $driverCode = $exception->errorInfo[1] ?? null;

        return match ($connection->getDriverName()) {
            'mysql' => $driverCode === 1205,
            'pgsql' => $exception->getCode() === '55P03',
            'sqlite' => $driverCode === 5,
            default => false,
        };
    }
}
