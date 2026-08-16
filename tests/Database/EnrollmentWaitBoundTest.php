<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * Enrollment retains its independent configured wait, but it no longer leaves
 * that value on a host-owned connection. BoundedLockWaitTest proves the setting
 * while the critical section runs; these integration cases prove every
 * EnrollmentGuard path restores the host value afterwards.
 */

/**
 * Read one engine setting back as text.
 *
 * scalar() is honestly typed mixed -- the drivers disagree about whether a
 * numeric setting comes back as an int or a string -- so this narrows it once,
 * loudly, rather than each caller guessing.
 */
function enrollmentWaitSetting(string $query): string
{
    $value = DB::connection()->scalar($query);

    return match (true) {
        is_int($value) => (string) $value,
        is_string($value) => $value,
        default => throw new RuntimeException('Non-scalar readback from: ' . $query),
    };
}

/** The lock bound the engine currently has set, in milliseconds. */
function enrollmentWaitBoundMs(): int
{
    return match (DB::connection()->getDriverName()) {
        'sqlite' => (int) enrollmentWaitSetting('PRAGMA busy_timeout'),
        'mysql' => (int) enrollmentWaitSetting('SELECT @@SESSION.innodb_lock_wait_timeout') * 1000,
        // Postgres reports its own units: '3s', '250ms', or '0' for "no bound".
        'pgsql' => enrollmentWaitPostgresMs(enrollmentWaitSetting('SHOW lock_timeout')),
        default => throw new RuntimeException('No lock-bound readback for this driver.'),
    };
}

function enrollmentWaitPostgresMs(string $shown): int
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
 * seconds is chosen to be a value no bounded enrollment in these tests can
 * produce.
 */
function parkEnrollmentWaitBound(): void
{
    $connection = DB::connection();

    match ($connection->getDriverName()) {
        'sqlite' => $connection->statement('PRAGMA busy_timeout = 47000'),
        'mysql' => $connection->statement('SET SESSION innodb_lock_wait_timeout = 47'),
        'pgsql' => $connection->statement("SET lock_timeout = '47s'"),
        default => throw new RuntimeException('No lock-bound readback for this driver.'),
    };

    // The park itself is load-bearing: if it silently failed, every assertion
    // below would be measuring a coincidence.
    expect(enrollmentWaitBoundMs())->toBe(47_000);
}

beforeEach(function (): void {
    parkEnrollmentWaitBound();
});

it('restores the host setting after using the configured bound', function (): void {
    (new EnrollmentGuard(DB::connection(), lockWaitSeconds: 3))
        ->serialize(7, 'password', 1, fn (): bool => true);

    expect(enrollmentWaitBoundMs())->toBe(47_000);
});

it('applies its documented default when the caller names no bound', function (): void {
    (new EnrollmentGuard(DB::connection()))
        ->serialize(7, 'password', 1, fn (): bool => true);

    expect(enrollmentWaitBoundMs())->toBe(47_000);
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

    expect(enrollmentWaitBoundMs())->toBe(47_000);
})->with(['zero' => [0], 'negative' => [-30]]);

it('restores the host setting when the lock row already exists', function (): void {
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

    expect(enrollmentWaitBoundMs())->toBe(47_000);
});
