<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/*
 * DatabaseMigrations, NOT RefreshDatabase — and this file exists ONLY because of
 * that difference.
 *
 * The test below drops a table to provoke a non-contention database error.
 * RefreshDatabase wraps each test in a transaction, and MySQL implicitly commits
 * on DDL: the drop silently ends the wrapping transaction, so Laravel's later
 * rollback fails with `SAVEPOINT trans2 does not exist` — a PDOException from
 * the test harness rather than the QueryException the guard is supposed to
 * rethrow. The assertion then fails for a reason that has nothing to do with the
 * code under test.
 *
 * SQLite and Postgres both support transactional DDL and passed either way,
 * which is precisely why this only surfaced on the MySQL leg of the matrix.
 */
uses(DatabaseMigrations::class);

it('does not disguise an unrelated database error as contention', function (): void {
    /*
     * A blanket QueryException -> Contended mapping would report a missing
     * table, a rejected session setting, or any future query defect as ordinary
     * enrollment contention. EnrollmentRefused::contended() tells the caller the
     * operation is safe to retry, which is exactly the wrong advice for a schema
     * problem — and on SQLite both failures carry the same SQLSTATE (HY000), so
     * nothing but the driver code separates them.
     */
    Schema::drop('auth_enrollment_locks');

    (new EnrollmentGuard(DB::connection(), lockWaitSeconds: 5))
        ->serialize(7, 'password', 1, fn (): bool => true);
})->throws(QueryException::class);
