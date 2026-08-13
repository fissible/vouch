<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\DatabaseAttemptStore;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthConnection;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

/*
 * DatabaseMigrations, NOT RefreshDatabase.
 *
 * RefreshDatabase wraps each test in a transaction on the default connection.
 * A second connection cannot see uncommitted rows from that transaction, so
 * every "racing" writer would operate on an empty table and every assertion
 * here would pass without anything having raced. That is the same vacuous
 * control this project has found repeatedly, wearing a different costume.
 * DatabaseMigrations migrates fresh per test and commits, so both connections
 * see the same data.
 */
uses(DatabaseMigrations::class);

beforeEach(function (): void {
    // Register the two contending connections up front so every test — not
    // only those going through storeOn() — can use them.
    $default = Config::string('database.default');
    $settings = Config::array('database.connections.' . $default);

    foreach (['race_a', 'race_b'] as $name) {
        config(['database.connections.' . $name => $settings]);
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Contention tests need a shared database. In-memory SQLite gives each '
            . 'connection its own, so these would pass without racing. Set '
            . 'VOUCH_SQLITE_PATH to a file, as the CI matrix does.',
        );
    }
});

/** A store bound to its own connection, so two of them genuinely contend. */
function storeOn(string $name): DatabaseAttemptStore
{
    return new DatabaseAttemptStore(DB::connection($name), new TransitionRules());
}

/**
 * @param array<string, mixed> $overrides
 */
function contendedAttempt(array $overrides = []): AuthAttempt
{
    return AuthAttempt::create(array_merge([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ], $overrides));
}

it('lets exactly one of two racing transitions win', function (): void {
    $attempt = contendedAttempt(['state' => AttemptState::Initiated]);

    // Both readers hold version 1.
    $a = AuthAttempt::findOrFail($attempt->id);
    $b = AuthAttempt::findOrFail($attempt->id);

    $first = storeOn('race_a')->transition($a, AttemptState::Identified);
    $second = storeOn('race_b')->transition($b, AttemptState::Identified);

    expect($first)->toBe(TransitionOutcome::Succeeded)
        ->and($second)->toBe(TransitionOutcome::ConcurrentModification)
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(2);
});

it('consumes a challenge exactly once under contention', function (): void {
    $attempt = contendedAttempt();
    $challenge = AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', '123456'),
        'expires_at' => now()->addMinutes(2),
    ]);

    $a = AuthAttempt::findOrFail($attempt->id);
    $b = AuthAttempt::findOrFail($attempt->id);

    $outcomes = [
        storeOn('race_a')->transition($a, AttemptState::FactorSatisfied, $challenge->id),
        storeOn('race_b')->transition($b, AttemptState::FactorSatisfied, $challenge->id),
    ];

    $succeeded = array_filter(
        $outcomes,
        fn (TransitionOutcome $o): bool => $o === TransitionOutcome::Succeeded,
    );

    expect($succeeded)->toHaveCount(1)
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(2);
});

it('leaves the challenge unconsumed when the losing writer rolls back', function (): void {
    // The most valuable test here: it proves the loser's challenge consumption
    // is rolled back, not merely that its transition failed. Without the
    // rollback, a lost race would burn a valid one-time code — a denial of
    // service against a legitimate user, invisible to a test that only asserts
    // on the transition outcome.
    $attempt = contendedAttempt();
    $challengeA = AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', 'aaa'),
        'expires_at' => now()->addMinutes(2),
    ]);
    $challengeB = AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', 'bbb'),
        'expires_at' => now()->addMinutes(2),
    ]);

    $a = AuthAttempt::findOrFail($attempt->id);
    $b = AuthAttempt::findOrFail($attempt->id);

    storeOn('race_a')->transition($a, AttemptState::FactorSatisfied, $challengeA->id);
    $loser = storeOn('race_b')->transition($b, AttemptState::FactorSatisfied, $challengeB->id);

    expect($loser)->toBe(TransitionOutcome::ConcurrentModification)
        ->and(AuthChallenge::findOrFail($challengeB->id)->consumed_at)->toBeNull()
        ->and(AuthChallenge::findOrFail($challengeA->id)->consumed_at)->not->toBeNull();
});

it('rejects a duplicate federated identity under concurrent insert', function (): void {
    $connection = AuthConnection::create([
        'tenant_id' => 'acme',
        'email_domain' => 'acme.example',
    ]);

    $row = [
        'connection_id' => $connection->id,
        'issuer' => 'https://idp.acme.example',
        'subject' => 'sub-1',
        'created_at' => now(),
        'updated_at' => now(),
    ];

    DB::connection('race_a')->table('auth_federated_identities')->insert($row);

    expect(fn () => DB::connection('race_b')->table('auth_federated_identities')->insert($row))
        ->toThrow(\Illuminate\Database\QueryException::class);
});
