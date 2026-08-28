<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\FirstCredentialEnrollment;
use Fissible\Vouch\Enrollment\FirstCredentialRequest;
use Fissible\Vouch\Enrollment\FirstCredentialResult;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthIdentifierVerificationOutbox;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Fissible\Vouch\Support\LockContention;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

/*
 * 2.3d Task 3's stated concurrency semantics, proven by genuinely interleaving
 * two connections. Two sequential calls prove idempotence and would pass with
 * EnrollmentGuard removed entirely, which is the mechanism the spec names.
 */

beforeEach(function (): void {
    $default = Config::string('database.default');
    $settings = Config::array('database.connections.' . $default);

    foreach (['first_a', 'first_b'] as $name) {
        config(['database.connections.' . $name => $settings]);
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Contention tests need a shared database. In-memory SQLite gives each connection '
            . 'its own, so these would pass without racing.',
        );
    }
});

function enrollmentOn(string $connection): FirstCredentialEnrollment
{
    return app()->makeWith(FirstCredentialEnrollment::class, [
        'connection' => DB::connection($connection),
    ]);
}

function firstRequest(int $userId, string $value, string $password = 'first-password'): FirstCredentialRequest
{
    return new FirstCredentialRequest(
        userId: $userId,
        identifierType: 'email',
        identifierValue: $value,
        password: $password,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

it('resolves a contended identifier claim to exactly one owner', function (): void {
    /*
     * A genuine interleave: A holds the identifier row inside an open
     * transaction while B attempts the same (type, value). The unique
     * constraint decides the winner, but the loser must be refused NEUTRALLY
     * rather than surfacing a driver error, which would hand the host an
     * oracle at its registration endpoint.
     */
    $a = DB::connection('first_a');
    $b = null;

    $a->beginTransaction();

    try {
        $a->table('auth_identifiers')->insert([
            'user_id' => 1,
            'type' => 'email',
            'value' => 'shared@acme.example',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $started = microtime(true);

        try {
            $b = enrollmentOn('first_b')->enroll(firstRequest(2, 'shared@acme.example'));
        } catch (QueryException $contention) {
            $b = $contention;
        }

        $elapsed = microtime(true) - $started;

        $a->commit();
    } catch (\Throwable $e) {
        $a->rollBack();

        throw $e;
    }

    /*
     * B is blocked by SQLite's database-wide write lock for as long as A holds
     * its transaction, so a durable decoy cannot be written and the bounded
     * wait must surface that. Asserting Accepted here would only be reachable
     * by swallowing the failure, which is the neutrality hole this suite
     * exists to prevent.
     *
     * The failure is asserted as VERIFIED lock contention, not merely as some
     * Throwable: a typo or a misconfiguration would otherwise satisfy this and
     * the test would report contention evidence it never observed.
     */
    expect($b)->toBeInstanceOf(QueryException::class);
    assert($b instanceof QueryException);

    /*
     * BOUNDED, on every engine. The identifier claim contends on the unique
     * index, and that wait is NOT covered by vouch.enrollment.lock_wait_seconds
     * today: EnrollmentGuard scopes BoundedLockWait to acquiring the
     * auth_enrollment_locks row, and BoundedLockWait::within() restores the
     * prior setting in a finally — so by the time this insert runs the bound
     * is gone.
     *
     * Measured, not inferred. On Postgres the blocked backend reports
     * wait_event_type=Lock, wait_event=transactionid with lock_timeout=0, and
     * waits forever. On MySQL the same wait takes 51s, which is InnoDB's
     * default innodb_lock_wait_timeout rather than anything Vouch chose.
     */
    /*
     * Derived from the configured bound, not a magic number: the requirement
     * is that lock_wait_seconds governs this wait rather than the engine's own
     * default.
     *
     * The slack has to satisfy two constraints that pull opposite ways. It
     * must stay well UNDER the smallest engine default this exists to catch —
     * MySQL's innodb_lock_wait_timeout at 50s, measured at 50.1s and 51.6s
     * before the fix — or it stops discriminating. And it must stay well OVER
     * what a loaded runner actually takes: this test costs 10.7s locally, and
     * a macOS CI runner recorded 20.2s, which flaked a +15 ceiling.
     *
     * +30 sits between them with room on both sides. It is deliberately not
     * tight: the assertion is about boundedness, not latency, and a latency
     * assertion on shared CI hardware is a flake generator.
     */
    expect($elapsed)->toBeLessThan(config()->integer('vouch.enrollment.lock_wait_seconds') + 30.0);

    expect(app(LockContention::class)->isVerified(DB::connection('first_b'), $b))->toBeTrue()
        ->and(AuthIdentifier::query()->where('value', 'shared@acme.example')->count())->toBe(1)
        ->and(AuthIdentifier::query()->where('value', 'shared@acme.example')->value('user_id'))->toBe(1)
        ->and(AuthCredential::query()->where('user_id', 2)->count())->toBe(0);
});

it('lets exactly one of two interleaved enrollments claim the password slot', function (): void {
    /*
     * Distinct identifiers, one user: the race is for PasswordFactor's single
     * active credential, not for the identifier. Reusing one address would
     * short-circuit on the unique constraint and never reach the capacity
     * branch EnrollmentGuard::serialize() exists to protect.
     */
    $a = DB::connection('first_a');
    $second = null;

    $a->beginTransaction();

    try {
        $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);
        $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'password')
            ->lockForUpdate()->first();

        try {
            $second = enrollmentOn('first_b')->enroll(firstRequest(7, 'second@acme.example', 'racing-password'));
        } catch (QueryException $contention) {
            $second = $contention;
        }

        $a->table('auth_credentials')->insert([
            'user_id' => 7,
            'type' => 'password',
            'secret' => 'digest',
            'strength' => 'knowledge',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $a->commit();
    } catch (\Throwable $e) {
        $a->rollBack();

        throw $e;
    }

    /*
     * The invariant is Accepted IF AND ONLY IF the durable decoy was persisted.
     *
     * An earlier revision of this test asserted a raw QueryException must
     * escape, which only ever held on SQLite. I then over-corrected and
     * asserted Accepted unconditionally — which is worse, because Accepted
     * would then be satisfied by an implementation that silently failed to
     * write the decoy. FirstCredentialResult has one case precisely so the
     * response says nothing; that guarantee is only honest if the decoy the
     * response implies actually exists.
     *
     * So: whichever way this engine resolves the standoff, the two must agree.
     * Measured both ways — MySQL persists the decoy and returns Accepted;
     * SQLite cannot, because its database-wide writer lock blocks the decoy
     * too, and it fails loudly rather than lying.
     */
    $decoys = AuthIdentifierVerificationOutbox::query()->count();

    if ($second instanceof QueryException) {
        expect($decoys)->toBe(0)
            ->and(app(LockContention::class)->isVerified(DB::connection('first_b'), $second))->toBeTrue();
    } else {
        expect($second)->toBe(FirstCredentialResult::Accepted)
            ->and($decoys)->toBeGreaterThan(0);
    }

    expect(AuthCredential::query()->where('user_id', 7)->where('type', 'password')
        ->whereNull('disabled_at')->count())->toBe(1);
});

it('answers a settled identifier collision neutrally, with a durable decoy', function (): void {
    /*
     * The path that has never been tested, and the one the neutrality
     * guarantee actually rests on. Every other test here holds A open so B can
     * only time out; B never observes the committed unique violation that a
     * real second registrant hits.
     *
     * A commits first. B then enrols the same identifier for a different user,
     * hits the unique index on a COMMITTED row, and must be told exactly what
     * the first registrant was told — Accepted, with a decoy — or the endpoint
     * discloses that the identifier is taken.
     *
     * This passes on all three engines, and the reason is worth recording
     * because it was predicted to fail and did not. write() READS the
     * identifier first and returns false when a committed row belongs to
     * someone else, so no insert is attempted and no unique violation occurs.
     * The neutral answer here comes from the read path, not from the violation
     * handler.
     *
     * That leaves a REAL latent gap this test does not reach.
     * isIdentifierUniqueViolation() matches SQLSTATE '23000' only, and PDO
     * reports '23505' for a Postgres unique violation — measured directly:
     * pgsql 23505, mysql 23000, sqlite 23000. It is reachable solely in the
     * read-then-insert race window, where a competing row commits between the
     * read above and the insert. On Postgres the driver error would then be
     * rethrown and the identifier disclosed. Closing that needs a test that
     * can hold the window open, which this one cannot.
     */
    DB::connection('first_a')->table('auth_identifiers')->insert([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'taken@acme.example',
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $second = enrollmentOn('first_b')->enroll(firstRequest(2, 'taken@acme.example'));

    expect($second)->toBe(FirstCredentialResult::Accepted)
        ->and(AuthIdentifierVerificationOutbox::query()->count())->toBeGreaterThan(0)
        ->and(AuthIdentifier::query()->where('value', 'taken@acme.example')->count())->toBe(1)
        ->and(AuthIdentifier::query()->where('value', 'taken@acme.example')->value('user_id'))->toBe(1)
        ->and(AuthCredential::query()->where('user_id', 2)->count())->toBe(0);
});

it('bounds a contended enrollment instead of hanging the request thread', function (): void {
    /*
     * config('vouch.enrollment.lock_wait_seconds') exists because "the engine
     * defaults are wildly inconsistent — MySQL waits 50s, Postgres waits
     * forever, SQLite fails immediately — and an unbounded wait hangs a
     * request thread". That is the config's own comment, and it is the
     * requirement under test here.
     *
     * Postgres does not honour it today: a contended enrollment blocks past
     * six minutes on a CI runner and past four minutes locally, so this test
     * HANGS there rather than failing. That cannot be rescued from inside PHP
     * — pcntl_alarm was tried and cannot fire, because signals are handled
     * between VM instructions and the process is blocked inside libpq. The
     * containment is `timeout-minutes` on the CI job; the fix is to make the
     * bound actually apply on Postgres.
     */
    Config::set('vouch.enrollment.lock_wait_seconds', 2);

    $a = DB::connection('first_a');
    $a->beginTransaction();

    try {
        $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 9, 'type' => 'password']]);
        $a->table('auth_enrollment_locks')->where('user_id', 9)->where('type', 'password')
            ->lockForUpdate()->first();

        $started = microtime(true);

        try {
            $second = enrollmentOn('first_b')->enroll(firstRequest(9, 'bounded@acme.example', 'racing-password'));
        } catch (QueryException $contention) {
            $second = $contention;
        }

        $elapsed = microtime(true) - $started;

        // Generous: the assertion is boundedness, not a specific latency. A
        // tight bound would be flaky on a loaded runner and would not describe
        // the defect, which is unboundedness.
        /*
         * Boundedness is the claim; the outcome follows the same
         * Accepted-iff-decoy invariant as the test above, because SQLite's
         * database-wide writer lock blocks the decoy write too and the
         * refusal is then correctly loud rather than a silent Accepted.
         */
        // Same ceiling and the same reasoning as the identifier test above.
        expect($elapsed)->toBeLessThan(config()->integer('vouch.enrollment.lock_wait_seconds') + 30.0);

        if ($second instanceof QueryException) {
            expect(AuthIdentifierVerificationOutbox::query()->count())->toBe(0);
        } else {
            expect($second)->toBe(FirstCredentialResult::Accepted)
                ->and(AuthIdentifierVerificationOutbox::query()->count())->toBeGreaterThan(0);
        }

        $a->rollBack();
    } catch (\Throwable $e) {
        if ($a->transactionLevel() > 0) {
            $a->rollBack();
        }

        throw $e;
    }
});
