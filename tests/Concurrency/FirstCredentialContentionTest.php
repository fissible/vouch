<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\FirstCredentialEnrollment;
use Fissible\Vouch\Enrollment\FirstCredentialRequest;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
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

        try {
            $b = enrollmentOn('first_b')->enroll(firstRequest(2, 'shared@acme.example'));
        } catch (QueryException $contention) {
            $b = $contention;
        }

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
     * Same shape, and the same discriminator: verified lock contention rather
     * than any Throwable. The invariant that matters is one active password
     * credential, whichever side wins.
     */
    expect($second)->toBeInstanceOf(QueryException::class);
    assert($second instanceof QueryException);

    expect(app(LockContention::class)->isVerified(DB::connection('first_b'), $second))->toBeTrue()
        ->and(AuthCredential::query()->where('user_id', 7)->where('type', 'password')
            ->whereNull('disabled_at')->count())->toBe(1);
});
