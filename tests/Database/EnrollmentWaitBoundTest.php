<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * boundTheWait() is the reason a contended enrollment refuses instead of hanging
 * a request thread. The existing contention test asserted the call returned in
 * under ten seconds, which is a wall-clock proxy: it passes with the bound
 * removed entirely on SQLite, whose default is to fail instantly anyway, and it
 * is skipped altogether on the in-memory database the suite runs on by default.
 *
 * These read the setting back out of the engine instead. That is the mechanism —
 * what the engine will actually do on the next contended statement — and it is
 * observable on every driver without needing a second connection to race.
 */

/**
 * Read one engine setting back as text.
 *
 * scalar() is honestly typed mixed -- the drivers disagree about whether a
 * numeric setting comes back as an int or a string -- so this narrows it once,
 * loudly, rather than each caller guessing.
 */
function readEngineSetting(string $query): string
{
    $value = DB::connection()->scalar($query);

    return match (true) {
        is_int($value) => (string) $value,
        is_string($value) => $value,
        default => throw new RuntimeException('Non-scalar readback from: ' . $query),
    };
}

/** The lock bound the engine currently has set, in milliseconds. */
function activeWaitBoundMs(): int
{
    return match (DB::connection()->getDriverName()) {
        'sqlite' => (int) readEngineSetting('PRAGMA busy_timeout'),
        'mysql', 'mariadb' => (int) readEngineSetting('SELECT @@SESSION.innodb_lock_wait_timeout') * 1000,
        // Postgres reports its own units: '3s', '250ms', or '0' for "no bound".
        'pgsql' => pgsqlIntervalToMs(readEngineSetting('SHOW lock_timeout')),
        default => throw new RuntimeException('No lock-bound readback for this driver.'),
    };
}

function pgsqlIntervalToMs(string $shown): int
{
    return match (true) {
        str_ends_with($shown, 'ms') => (int) $shown,
        str_ends_with($shown, 's') => (int) $shown * 1000,
        default => (int) $shown,
    };
}

/**
 * Move the engine off any plausible correct answer before each test.
 *
 * Without this the assertions would be satisfied by a setting nobody set. 47
 * seconds is chosen to be a value no arm of boundTheWait() can produce.
 */
function parkWaitBound(): void
{
    $connection = DB::connection();

    match ($connection->getDriverName()) {
        'sqlite' => $connection->statement('PRAGMA busy_timeout = 47000'),
        'mysql', 'mariadb' => $connection->statement('SET SESSION innodb_lock_wait_timeout = 47'),
        'pgsql' => $connection->statement("SET lock_timeout = '47s'"),
        default => throw new RuntimeException('No lock-bound readback for this driver.'),
    };

    // The park itself is load-bearing: if it silently failed, every assertion
    // below would be measuring a coincidence.
    expect(activeWaitBoundMs())->toBe(47_000);
}

beforeEach(function (): void {
    parkWaitBound();
});

it('applies the configured bound to the engine', function (): void {
    (new EnrollmentGuard(DB::connection(), lockWaitSeconds: 3))
        ->serialize(7, 'password', 1, fn (): bool => true);

    // Seconds in, milliseconds out on SQLite: the conversion is the assertion.
    expect(activeWaitBoundMs())->toBe(3_000);
});

it('applies its documented default when the caller names no bound', function (): void {
    (new EnrollmentGuard(DB::connection()))
        ->serialize(7, 'password', 1, fn (): bool => true);

    expect(activeWaitBoundMs())->toBe(5_000);
});

it('floors a zero or negative bound rather than passing it through', function (int $configured): void {
    /*
     * A zero bound means "no timeout" on Postgres and "fail immediately" on
     * MySQL — opposite behaviours from the same number, and neither is what a
     * host that configured 0 by accident would want. The floor is what makes the
     * setting safe to expose in config.
     */
    (new EnrollmentGuard(DB::connection(), lockWaitSeconds: $configured))
        ->serialize(7, 'password', 1, fn (): bool => true);

    expect(activeWaitBoundMs())->toBe(1_000);
})->with(['zero' => [0], 'negative' => [-30]]);

it('bounds the wait on the path that refuses, not only the path that succeeds', function (): void {
    /*
     * acquire() sets the bound and claims the lock inside the same try block. If
     * the two were ever reordered, the bound would be applied only after the
     * statement it is supposed to bound had already run.
     */
    $connection = DB::connection();

    // A pre-existing lock row makes insertOrIgnore a no-op, so this exercises
    // the same ordering against an already-claimed subject.
    $connection->table('auth_enrollment_locks')->insert(['user_id' => 7, 'type' => 'totp']);

    (new EnrollmentGuard($connection, lockWaitSeconds: 2))
        ->serialize(7, 'totp', 1, fn (): bool => true);

    expect(activeWaitBoundMs())->toBe(2_000);
});
