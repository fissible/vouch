<?php

declare(strict_types=1);

use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\DatabaseRowLock;
use Fissible\Vouch\Support\LockContention;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

beforeEach(function (): void {
    $default = Config::string('database.default');
    $settings = Config::array('database.connections.' . $default);

    foreach (['row_lock_a', 'row_lock_b', 'row_lock_c'] as $name) {
        config(['database.connections.' . $name => $settings]);
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'The committed-row lock probe needs separate connections to one file-backed database.',
        );
    }
});

it('distinguishes a committed-row FOR UPDATE lock from the no-lock path', function (): void {
    $a = DB::connection('row_lock_a');
    $b = DB::connection('row_lock_b');
    $c = DB::connection('row_lock_c');
    $driver = $a->getDriverName();

    DB::table('auth_enrollment_locks')->insert([
        'user_id' => 700,
        'type' => 'password',
    ]);

    $a->beginTransaction();
    $a->table('auth_enrollment_locks')
        ->where('user_id', 700)
        ->where('type', 'password')
        ->lockForUpdate()
        ->first();

    $bounded = static function (Connection $connection, \Closure $operation): bool {
        try {
            (new BoundedLockWait($connection))->shared(
                static function () use ($connection, $operation): void {
                    $connection->beginTransaction();

                    try {
                        $operation();
                        $connection->commit();
                    } catch (\Throwable $exception) {
                        $connection->rollBack();

                        throw $exception;
                    }
                },
            );

            return false;
        } catch (\Throwable $exception) {
            if ($exception instanceof QueryException) {
                return (new LockContention())->isVerified($connection, $exception);
            }

            // SQLite may surface the bounded write failure as PDOException
            // during transaction commit rather than as QueryException.
            return $connection->getDriverName() === 'sqlite'
                && $exception instanceof \PDOException
                && ($exception->getCode() === 5
                    || ($exception->errorInfo[1] ?? null) === 5);
        }
    };

    try {
        $noLockContended = $bounded($b, static function () use ($b): void {
            $b->table('auth_enrollment_locks')
                ->where('user_id', 700)
                ->where('type', 'password')
                ->first();
        });

        $primitiveContended = $bounded($c, static function () use ($c): void {
            (new DatabaseRowLock($c))->ensureAndLock(
                'auth_enrollment_locks',
                ['user_id' => 700, 'type' => 'password'],
                ['user_id' => 700, 'type' => 'password'],
            );
        });
    } finally {
        $a->rollBack();
        if ($b->transactionLevel() > 0) {
            $b->rollBack();
        }
        if ($c->transactionLevel() > 0) {
            $c->rollBack();
        }
        $a->disconnect();
        $b->disconnect();
        $c->disconnect();
    }

    expect(in_array($driver, ['pgsql', 'mysql', 'sqlite'], true))->toBeTrue()
        // SQLite reports contention from its database-wide write lock; it
        // cannot establish that FOR UPDATE itself is load-bearing.
        ->and($primitiveContended)->toBeTrue();

    // A plain read does not wait on another transaction's row lock. The
    // primitive's ensure-and-lock path is the operation under test; MySQL's
    // conflicting-index behavior is intentionally not used as the baseline.
    expect($noLockContended)->toBeFalse();
});
