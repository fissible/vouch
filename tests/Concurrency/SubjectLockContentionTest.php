<?php

declare(strict_types=1);

use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Tokens\CredentialLockManager;
use Fissible\Vouch\Tokens\SubjectKey;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

/*
 * 2.4 Task 5a — whether the subject lock actually excludes, proven by
 * interleaving two connections rather than by reasoning about SQL.
 *
 * Two sequential acquisitions prove nothing: they pass with the lock removed
 * entirely. The claim under test is about a database's behaviour, so it is
 * asserted against a database, on every engine the package supports.
 */

beforeEach(function (): void {
    $default = Config::string('database.default');
    $settings = Config::array('database.connections.' . $default);

    foreach (['subject_a', 'subject_b'] as $name) {
        config(['database.connections.' . $name => $settings]);
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Contention tests need a shared database. In-memory SQLite gives each connection '
            . 'its own, so these would pass without racing.',
        );
    }

    /*
     * A missing table would otherwise READ AS EXCLUSION: the acquisition throws,
     * and a test that treats "it threw" as "it was blocked" passes for entirely
     * the wrong reason. Assert the anchor exists before any contention claim
     * rests on a failure to reach it.
     */
    expect(DB::connection()->getSchemaBuilder()->hasTable('auth_subject_locks'))->toBeTrue();
});

/**
 * Attempt an acquisition on $connection and report whether it was BLOCKED.
 *
 * Only a driver-verified lock/timeout condition counts. Anything else — a
 * missing table, a typo, a bad binding — is rethrown, because "the statement
 * failed" and "another holder excluded me" are different claims and only one of
 * them is what these tests assert.
 *
 * The SQLite branch mirrors DatabaseRowLockContentionTest: SQLite surfaces a
 * bounded write failure as PDOException code 5 (SQLITE_BUSY) at COMMIT rather
 * than as a QueryException on the statement, so classifying on QueryException
 * alone would make a correct implementation look broken on one engine.
 *
 * @param list<string> $credentialIds
 */
function attemptSubjectLock(Connection $connection, SubjectKey $subject, array $credentialIds = []): bool
{
    /*
     * The bound is set INSIDE the transaction. PostgreSQL's SET LOCAL applies to
     * the current transaction and is silently a no-op outside one, which would
     * leave this attempt on the default unbounded wait — a contention test that
     * hangs CI instead of failing it. That is the failure mode that already
     * forced this job to a 35-minute timeout once.
     */
    $connection->beginTransaction();

    try {
        $connection->statement(match ($connection->getDriverName()) {
            'mysql', 'mariadb' => 'SET SESSION innodb_lock_wait_timeout = 1',
            'pgsql' => "SET LOCAL lock_timeout = '1s'",
            // SQLite has no per-statement lock timeout; it inherits the
            // connection's busy timeout, which is already bounded.
            default => 'SELECT 1',
        });

        app(CredentialLockManager::class)->acquire($connection, $subject, $credentialIds);
        $connection->commit();

        return false;
    } catch (\Throwable $exception) {
        try {
            $connection->rollBack();
        } catch (\Throwable) {
            // A timed-out PostgreSQL transaction is already aborted.
        }

        if ($exception instanceof QueryException) {
            if (! (new LockContention())->isVerified($connection, $exception)) {
                throw $exception;
            }

            return true;
        }

        if ($connection->getDriverName() === 'sqlite'
            && $exception instanceof \PDOException
            && ($exception->getCode() === 5 || ($exception->errorInfo[1] ?? null) === 5)) {
            return true;
        }

        throw $exception;
    } finally {
        // MySQL's setting is SESSION-scoped and these named connections are
        // reused across tests, so leaving it at 1 would silently shorten every
        // later lock wait on the same connection.
        if (in_array($connection->getDriverName(), ['mysql', 'mariadb'], true)) {
            $connection->statement('SET SESSION innodb_lock_wait_timeout = DEFAULT');
        }
    }
}

it('excludes a second holder of the same subject that has no session row', function (): void {
    /*
     * The whole point of 5a. A holds the subject anchor inside an open
     * transaction; B must be blocked. Under the shipped lock both would
     * "succeed" because neither locked anything: there is no session row to
     * lock, and ->first() over an empty result is silent.
     */
    $subject = SubjectKey::of('App\\Models\\User', '7');
    $a = DB::connection('subject_a');
    $b = DB::connection('subject_b');

    expect(DB::table('auth_sessions')->count())->toBe(0);

    $a->beginTransaction();
    app(CredentialLockManager::class)->acquire($a, $subject, []);

    try {
        expect(attemptSubjectLock($b, $subject))->toBeTrue();
    } finally {
        $a->rollBack();
    }
});

it('does not make two different subjects contend', function (): void {
    /*
     * The other half, and the one a too-coarse anchor breaks: a single global
     * lock row would pass the exclusion test above and serialize the entire
     * application. Different providers with the SAME id are the sharpest case,
     * since a user_id-keyed anchor merges them.
     */
    $a = DB::connection('subject_a');
    $b = DB::connection('subject_b');

    $a->beginTransaction();
    app(CredentialLockManager::class)->acquire($a, SubjectKey::of('App\\Models\\User', '7'), []);

    try {
        expect(attemptSubjectLock($b, SubjectKey::of('App\\Models\\Admin', '7')))->toBeFalse();
    } finally {
        $a->rollBack();
    }
});

it('serializes the anchor claim itself, not only an existing anchor', function (): void {
    /*
     * The first-acquisition race, which is the one row locks alone cannot fix:
     * SELECT ... FOR UPDATE locks the rows that exist, and here there are none.
     * Both connections claim the anchor for a subject that has never been
     * locked before; exactly one row must result and the second must be
     * excluded rather than inserting a duplicate.
     *
     * DatabaseRowLock's ensure-then-lock is documented to require exactly this
     * matrix test: engines differ on which statement serializes.
     */
    $subject = SubjectKey::of('App\\Models\\User', '99');
    $a = DB::connection('subject_a');
    $b = DB::connection('subject_b');

    expect(DB::table('auth_subject_locks')->where('subject_key', $subject->toString())->count())->toBe(0);

    $a->beginTransaction();
    app(CredentialLockManager::class)->acquire($a, $subject, []);

    try {
        expect(attemptSubjectLock($b, $subject))->toBeTrue();
    } finally {
        $a->commit();
    }

    expect(DB::table('auth_subject_locks')->where('subject_key', $subject->toString())->count())->toBe(1);
});
