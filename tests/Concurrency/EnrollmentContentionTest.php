<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Enrollment\EnrollmentRefusalReason;
use Fissible\Vouch\Enrollment\EnrollmentRefused;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

/*
 * DatabaseMigrations, NOT RefreshDatabase — the same reason as
 * AttemptStoreContentionTest. RefreshDatabase wraps each test in a transaction
 * on the default connection, so a second connection cannot see its uncommitted
 * rows and every "racing" writer would operate on an empty table. Every
 * assertion here would pass without anything having raced.
 */
uses(DatabaseMigrations::class);

beforeEach(function (): void {
    $default = Config::string('database.default');
    $settings = Config::array('database.connections.' . $default);

    foreach (['enroll_a', 'enroll_b'] as $name) {
        config(['database.connections.' . $name => $settings]);
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Contention tests need a shared database. In-memory SQLite gives each connection '
            . 'its own, so these would pass without racing. Set VOUCH_SQLITE_PATH to a file, '
            . 'as the CI matrix does.',
        );
    }
});

function guardOn(string $connection, int $wait = 2): EnrollmentGuard
{
    return new EnrollmentGuard(DB::connection($connection), lockWaitSeconds: $wait);
}

function makeCredentialOn(string $connection, string $type = 'password'): void
{
    DB::connection($connection)->table('auth_credentials')->insert([
        'user_id' => 7,
        'type' => $type,
        'secret' => 'digest',
        'strength' => 'knowledge',
        'created_at' => now(),
        'updated_at' => now(),
    ]);
}

it('lets exactly one of two interleaved password enrollments win', function (): void {
    /*
     * A genuine interleave, not two sequential calls. Connection A opens its
     * transaction and holds the lock; B then attempts the same subject. Whether
     * B blocks-then-refuses (MySQL, Postgres) or fails to acquire (SQLite,
     * where lockForUpdate is a no-op and the database-level write lock does the
     * work), the invariant is identical: one active credential.
     */
    $a = DB::connection('enroll_a');
    $refusal = null;

    $a->beginTransaction();

    try {
        $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);
        $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'password')
            ->lockForUpdate()->first();

        try {
            guardOn('enroll_b')->serialize(7, 'password', 1, function (): void {
                makeCredentialOn('enroll_b');
            });
        } catch (EnrollmentRefused $e) {
            $refusal = $e;
        }

        makeCredentialOn('enroll_a');
        $a->commit();
    } catch (\Throwable $e) {
        $a->rollBack();

        throw $e;
    }

    expect($refusal)->toBeInstanceOf(EnrollmentRefused::class)
        ->and(AuthCredential::where('user_id', 7)->where('type', 'password')->whereNull('disabled_at')->count())
        ->toBe(1);
});

it('serializes a re-enrollment, where the lock row already exists', function (): void {
    /*
     * The case every other test in this file misses, and the one production
     * spends most of its time in.
     *
     * Everywhere above, the lock row does not exist when the racers start, so
     * A's insertOrIgnore creates it and B's insertOrIgnore blocks on the
     * duplicate key. B is refused by the INSERT and never reaches the
     * lockForUpdate at all -- which is why removing that call leaves all four
     * of those tests passing on MySQL and Postgres.
     *
     * Nothing ever deletes from auth_enrollment_locks: the guard only ever
     * insertOrIgnores, and vouch:prune does not touch the table. So the row
     * survives the first enrollment for a subject, and every enrollment after
     * that one takes this path -- insertOrIgnore is a no-op that takes no lock,
     * and SELECT ... FOR UPDATE is the only thing standing between two writers.
     *
     * Seeded committed, outside either racer's transaction, so both see it.
     */
    DB::table('auth_enrollment_locks')->insert([['user_id' => 7, 'type' => 'password']]);

    $a = DB::connection('enroll_a');
    $refusal = null;

    $a->beginTransaction();

    try {
        // A's insertOrIgnore is a no-op here. The FOR UPDATE is the whole claim.
        $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);
        $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'password')
            ->lockForUpdate()->first();

        try {
            guardOn('enroll_b')->serialize(7, 'password', 1, function (): void {
                makeCredentialOn('enroll_b');
            });
        } catch (EnrollmentRefused $e) {
            $refusal = $e;
        }

        makeCredentialOn('enroll_a');
        $a->commit();
    } catch (\Throwable $e) {
        $a->rollBack();

        throw $e;
    }

    expect($refusal)->toBeInstanceOf(EnrollmentRefused::class)
        ->and(AuthCredential::where('user_id', 7)->where('type', 'password')->whereNull('disabled_at')->count())
        ->toBe(1);
});

it('refuses cleanly rather than surfacing a driver error', function (): void {
    // Without the QueryException -> EnrollmentRefused mapping, "somebody else is
    // enrolling right now" reaches the caller as SQLSTATE noise and becomes
    // indistinguishable from a database outage.
    $a = DB::connection('enroll_a');
    $a->beginTransaction();
    $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'totp']]);
    $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'totp')->lockForUpdate()->first();

    try {
        guardOn('enroll_b')->serialize(7, 'totp', 1, fn (): bool => true);
        $this->fail('Expected EnrollmentRefused.');
    } catch (EnrollmentRefused $refused) {
        expect($refused->reason)->toBe(EnrollmentRefusalReason::Contended);
    } finally {
        $a->rollBack();
    }
});

it('bounds the wait rather than hanging the caller', function (): void {
    /*
     * Engine defaults are wildly inconsistent -- MySQL waits 50s, Postgres waits
     * forever, SQLite fails instantly -- so an unbounded wait would hang a
     * request thread on every contended enrollment.
     *
     * The direct BoundedLockWait tests own the setting/readback proof. This test
     * retains what they cannot provide: a real held lock, a bounded return, a
     * typed refusal, and proof that enrollment restores the host connection.
     */
    $a = DB::connection('enroll_a');
    $b = DB::connection('enroll_b');

    // scalar() is honestly typed mixed: the drivers disagree about whether a
    // numeric setting returns an int or a string.
    $setting = static function (string $query) use ($b): string {
        $value = $b->scalar($query);

        return match (true) {
            is_int($value) => (string) $value,
            is_string($value) => $value,
            default => throw new RuntimeException('Non-scalar readback from: ' . $query),
        };
    };

    $readCurrent = static fn (): string => match ($b->getDriverName()) {
        'sqlite' => $setting('PRAGMA busy_timeout'),
        'mysql' => $setting('SELECT @@SESSION.innodb_lock_wait_timeout'),
        'pgsql' => $setting('SHOW lock_timeout'),
        default => throw new RuntimeException('No lock-wait readback for this driver.'),
    };
    $setCurrent = static function (string $value) use ($b): void {
        match ($b->getDriverName()) {
            'sqlite' => $b->statement(sprintf('PRAGMA busy_timeout = %d', (int) $value)),
            'mysql' => $b->statement(
                sprintf('SET SESSION innodb_lock_wait_timeout = %d', (int) $value),
            ),
            'pgsql' => $b->scalar("SELECT set_config('lock_timeout', ?, false)", [$value]),
            default => throw new RuntimeException('No lock-wait setter for this driver.'),
        };
    };
    $original = $readCurrent();
    $parked = match ($b->getDriverName()) {
        'sqlite' => '7000',
        'mysql' => '7',
        'pgsql' => '7s',
        default => throw new RuntimeException('No lock-wait setting for this driver.'),
    };
    $setCurrent($parked);

    expect($readCurrent())->toBe($parked);

    $a->beginTransaction();
    $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);
    $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'password')->lockForUpdate()->first();

    $started = microtime(true);
    $refusal = null;
    $after = null;

    try {
        try {
            guardOn('enroll_b', wait: 1)->serialize(7, 'password', 1, fn (): bool => true);
        } catch (EnrollmentRefused $exception) {
            $refusal = $exception;
        }
    } finally {
        $a->rollBack();
        $after = $readCurrent();
        $setCurrent($original);
    }

    expect($refusal)->toBeInstanceOf(EnrollmentRefused::class)
        ->and($after)->toBe($parked)
        ->and(microtime(true) - $started)->toBeLessThan(5.0);
});

it('never leaves two recovery-code generations live under interleaved regeneration', function (): void {
    /*
     * The dangerous case, and the one that needs the most care to test honestly.
     *
     * An earlier draft ran the two regenerations SEQUENTIALLY and asserted on the
     * result. That cannot detect the race it describes: gen-a fully commits
     * before gen-b starts, so the test passes with the enrollment lock removed
     * entirely. It measured nothing.
     *
     * It also matters WHERE A's disable half sits. Once A has disabled an
     * existing set, it holds InnoDB row locks on those rows, and B blocks on
     * THOSE regardless of the enrollment lock -- so a seeded fixture would again
     * pass without the lock. The window the enrollment lock uniquely covers is
     * the one with no pre-existing rows: A's disable affects zero rows, takes no
     * row locks, and nothing but the lock row stands between two writers each
     * inserting a full set. That is the same first-enrollment hole spec §2
     * describes for SELECT ... FOR UPDATE, arriving through regeneration.
     *
     * So: no seed, and A's disable runs BEFORE B is invoked. With the lock, B is
     * refused and exactly one generation survives. Without it, B commits ten
     * gen-b rows that A's already-executed disable can no longer catch, A adds
     * ten gen-a rows, and the assertions fail on all three counts -- twenty
     * active, two generations, and no refusal.
     */
    $disableActive = static function (string $connection): void {
        DB::connection($connection)->table('auth_credentials')
            ->where('user_id', 7)->where('type', 'recovery_code')->whereNull('disabled_at')
            ->update(['disabled_at' => now()]);
    };

    $seed = static function (string $connection, string $generation): void {
        $rows = [];

        for ($i = 0; $i < 10; $i++) {
            $rows[] = [
                'user_id' => 7,
                'type' => 'recovery_code',
                'secret' => $generation . '-' . $i,
                'strength' => 'recovery',
                'created_at' => now(),
                'updated_at' => now(),
            ];
        }

        DB::connection($connection)->table('auth_credentials')->insert($rows);
    };

    $a = DB::connection('enroll_a');
    $refusal = null;

    $a->beginTransaction();

    try {
        // A claims and holds the lock for this subject.
        $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'recovery_code']]);
        $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'recovery_code')
            ->lockForUpdate()->first();

        // A's disable half, before B is invoked. Zero rows, so zero row locks.
        $disableActive('enroll_a');

        // B attempts a complete regeneration through the REAL guard.
        try {
            guardOn('enroll_b')->serialize(7, 'recovery_code', 10, static function () use ($disableActive, $seed): void {
                $disableActive('enroll_b');
                $seed('enroll_b', 'gen-b');
            });
        } catch (EnrollmentRefused $e) {
            $refusal = $e;
        }

        // A's create half completes after B's attempt, then A releases.
        $seed('enroll_a', 'gen-a');
        $a->commit();
    } catch (\Throwable $e) {
        $a->rollBack();

        throw $e;
    }

    /*
     * Read back through the query builder, not the model.
     *
     * The seeds above insert generation-tagged plaintext directly, bypassing
     * AuthCredential's `encrypted` cast — reading them back through Eloquent
     * would try to decrypt a value that was never encrypted and throw
     * DecryptException. Insert and readback have to agree on the layer. The
     * cast itself is exercised by the driver tests; what this test is about is
     * which generation survived, so raw values are exactly what it wants.
     */
    $active = DB::table('auth_credentials')
        ->where('user_id', 7)
        ->where('type', 'recovery_code')
        ->whereNull('disabled_at')
        ->pluck('secret')
        ->all();

    // assert() rather than a cast: the query builder's pluck() yields mixed,
    // unlike Eloquent's, and PHPStan runs over tests at level 9. Same narrowing
    // convention as tests/Kernel/Policy/PolicyParserTest.php.
    $generations = array_values(array_unique(array_map(
        static function (mixed $secret): string {
            assert(is_string($secret));

            return substr($secret, 0, 5);
        },
        $active,
    )));

    expect($refusal)->toBeInstanceOf(EnrollmentRefused::class)
        ->and($active)->toHaveCount(10)
        ->and($generations)->toBe(['gen-a']);
});
