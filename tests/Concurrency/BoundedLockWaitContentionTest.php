<?php

declare(strict_types=1);

use Fissible\Vouch\Support\BoundedLockWait;
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

    foreach (['bounded_a', 'bounded_b'] as $name) {
        config(['database.connections.' . $name => $settings]);
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'The bounded-lock contention proof needs two connections to one file-backed database.',
        );
    }
});

function boundedContentionSetting(Connection $connection): int|string
{
    $value = match ($connection->getDriverName()) {
        'sqlite' => $connection->scalar('PRAGMA busy_timeout'),
        'mysql' => $connection->scalar('SELECT @@SESSION.innodb_lock_wait_timeout'),
        'pgsql' => $connection->scalar('SHOW lock_timeout'),
        default => throw new RuntimeException('Unsupported database driver.'),
    };

    if (! is_int($value) && ! is_string($value)) {
        throw new RuntimeException('The database returned a non-scalar lock-wait setting.');
    }

    return $value;
}

function setBoundedContentionSetting(Connection $connection, int|string $value): void
{
    match ($connection->getDriverName()) {
        'sqlite' => $connection->statement(sprintf('PRAGMA busy_timeout = %d', (int) $value)),
        'mysql' => $connection->statement(
            sprintf('SET SESSION innodb_lock_wait_timeout = %d', (int) $value),
        ),
        'pgsql' => $connection->scalar(
            "SELECT set_config('lock_timeout', ?, false)",
            [(string) $value],
        ),
        default => throw new RuntimeException('Unsupported database driver.'),
    };
}

it('restores the host setting after verified lock contention', function (): void {
    $a = DB::connection('bounded_a');
    $b = DB::connection('bounded_b');
    $prior = boundedContentionSetting($b);
    $parked = match ($b->getDriverName()) {
        'sqlite' => 47_000,
        'mysql' => 47,
        'pgsql' => '47s',
        default => throw new RuntimeException('Unsupported database driver.'),
    };

    setBoundedContentionSetting($b, $parked);
    expect(boundedContentionSetting($b))->toBe($parked);

    DB::table('auth_enrollment_locks')->insert(['user_id' => 7, 'type' => 'password']);

    $a->beginTransaction();
    $a->table('auth_enrollment_locks')
        ->where('user_id', 7)
        ->where('type', 'password')
        ->lockForUpdate()
        ->first();

    $caught = null;
    $after = null;
    $started = microtime(true);

    try {
        try {
            (new BoundedLockWait($b))->shared(function () use ($b): void {
                // SQLite's lockForUpdate is a bare SELECT, so the no-op insert is
                // intentionally retained: it is the statement that encounters
                // SQLite's global writer lock. Postgres reaches the FOR UPDATE;
                // MySQL may contend on either, and both are valid acquisition paths.
                $b->table('auth_enrollment_locks')
                    ->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);

                $b->table('auth_enrollment_locks')
                    ->where('user_id', 7)
                    ->where('type', 'password')
                    ->lockForUpdate()
                    ->first();
            });
        } catch (QueryException $exception) {
            $caught = $exception;
        }
    } finally {
        $a->rollBack();
        $after = boundedContentionSetting($b);
        setBoundedContentionSetting($b, $prior);
    }

    expect($caught)->toBeInstanceOf(QueryException::class);

    if (! $caught instanceof QueryException) {
        throw new RuntimeException('The contention proof did not produce a QueryException.');
    }

    expect((new LockContention())->isVerified($b, $caught))->toBeTrue()
        ->and($after)->toBe($parked)
        ->and(microtime(true) - $started)->toBeLessThan(10.0);
});
