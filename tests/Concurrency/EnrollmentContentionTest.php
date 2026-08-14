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
     * Two assertions, because neither alone is enough. The elapsed time is a
     * liveness check and nothing more: on SQLite the default behaviour is to
     * fail instantly, so a fast return is exactly what REMOVING the bound
     * produces. The setting readback is the mechanism -- it is what the engine
     * would actually have done had the lock cleared -- and this is the one place
     * it is read under genuine contention rather than after a quiet enrollment.
     */
    $a = DB::connection('enroll_a');
    $a->beginTransaction();
    $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);
    $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'password')->lockForUpdate()->first();

    $started = microtime(true);

    try {
        guardOn('enroll_b', wait: 2)->serialize(7, 'password', 1, fn (): bool => true);
    } catch (EnrollmentRefused) {
        // expected
    } finally {
        $a->rollBack();
    }

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

    $applied = match ($b->getDriverName()) {
        // Milliseconds on SQLite: the seconds-to-milliseconds conversion, read
        // back off the connection that actually contended.
        'sqlite' => (int) $setting('PRAGMA busy_timeout'),
        'mysql', 'mariadb' => (int) $setting('SELECT @@SESSION.innodb_lock_wait_timeout') * 1000,
        // Postgres reverts SET LOCAL on commit, so the bound is no longer
        // readable here. The dedicated readback test covers that engine.
        default => 2_000,
    };

    expect($applied)->toBe(2_000)
        ->and(microtime(true) - $started)->toBeLessThan(10.0);
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

