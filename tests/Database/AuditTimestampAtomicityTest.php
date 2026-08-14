<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\AdvanceCredentialTimestep;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * last_used_at is operational metadata, kept deliberately and documented as such
 * in the 2.2 spec -- explicitly NOT the replay guard, which is
 * last_used_timestep. That makes it audit data with a contract rather than a
 * spare column: it must advance exactly when the mutation carrying it commits,
 * and must not move when the enclosing compare-and-swap fails.
 *
 * The second half is the one worth testing. An audit timestamp that advances on
 * a FAILED transition records a use that never happened, and a credential-use
 * log nobody can trust is worse than none -- it is evidence in an investigation.
 *
 * These also cover the write itself: the update is a raw query-builder call,
 * which does NOT maintain timestamps automatically, so the columns genuinely
 * stop moving if the keys are dropped from the payload.
 */

function auditAttempt(): AuthAttempt
{
    // refresh(), because `version` comes from the DATABASE default and the model
    // instance does not know it until it is read back. Without this the CAS
    // compares against null and loses -- which is a real trap, not a fixture
    // quirk: it is the same schema-default interaction the version survivor's
    // disposition rests on.
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'user_id' => 7,
        'bound_context' => str_repeat('t', 64),
        'expires_at' => now()->addMinutes(10),
    ])->refresh();
}

function auditCredential(): AuthCredential
{
    return AuthCredential::create([
        'user_id' => 7,
        'type' => 'totp',
        'secret' => 'seed',
        'strength' => 'possession',
    ]);
}

it('advances the audit timestamp when the transition commits', function (): void {
    $attempt = auditAttempt();
    $credential = auditCredential();

    expect($credential->last_used_at)->toBeNull();

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 12_345),
    );

    $credential->refresh();

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and($credential->last_used_timestep)->toBe(12_345)
        ->and($credential->last_used_at)->not->toBeNull();
});

it('leaves the audit timestamp untouched when the compare-and-swap loses', function (): void {
    /*
     * The version is bumped behind the store's back, which is exactly what a
     * concurrent writer does. The real CAS then loses -- no double, no
     * fabricated outage.
     *
     * Both columns must be unchanged. Recording a use for an authentication that
     * did not happen would put a false entry in the one log an investigation
     * would rely on.
     */
    $attempt = auditAttempt();
    $credential = auditCredential();

    DB::table('auth_attempts')->where('id', $attempt->id)->update(['version' => $attempt->version + 1]);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 12_345),
    );

    $credential->refresh();

    expect($outcome)->not->toBe(TransitionOutcome::Succeeded)
        ->and($credential->last_used_timestep)->toBeNull()
        ->and($credential->last_used_at)->toBeNull();
});

/*
 * updated_at gets the same explicit decision rather than being carried along.
 *
 * It IS trustworthy transactional metadata here, and the reason is specific to
 * this code path: these mutations are raw query-builder updates, which bypass
 * Eloquent and therefore do NOT maintain timestamps. A row whose contents change
 * while updated_at stays put is a column that lies -- it reports the row as older
 * than it is, and anything reading it (incremental sync, cache invalidation, or
 * an engineer asking what changed recently) is misled by exactly the writes that
 * matter most.
 *
 * So it holds the same contract as last_used_at: advance on commit, do not move
 * when the compare-and-swap loses.
 */

/** Backdate a credential so a later write is observable. */
function backdatedCredential(): AuthCredential
{
    $credential = auditCredential();

    DB::table('auth_credentials')->where('id', $credential->id)
        ->update(['updated_at' => now()->subDay()]);

    return $credential->refresh();
}

it('advances the row timestamp when the transition commits', function (): void {
    $attempt = auditAttempt();
    $credential = backdatedCredential();
    $before = $credential->updated_at;

    app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 12_345),
    );

    expect($credential->refresh()->updated_at->greaterThan($before))->toBeTrue();
});

it('leaves the row timestamp untouched when the compare-and-swap loses', function (): void {
    $attempt = auditAttempt();
    $credential = backdatedCredential();
    $before = $credential->updated_at;

    DB::table('auth_attempts')->where('id', $attempt->id)->update(['version' => $attempt->version + 1]);

    app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 12_345),
    );

    expect($credential->refresh()->updated_at->equalTo($before))->toBeTrue();
});

it('refuses and mutates nothing when the attempt row vanishes before the guarded write', function (): void {
    /*
     * The vanished-row arm. The store re-reads the attempt by id before doing
     * anything else, so the race it defends against is a caller holding a loaded
     * attempt whose row is swept -- by an expiry job, a cascade, or an operator
     * -- between load and transition.
     *
     * Reproduced with the same standard as the CAS-loss cases: a valid, current
     * attempt is loaded, and only then does the row go away. Nothing is stubbed,
     * and the store performs its own real read.
     *
     * The assertion is not just the return value. A refusal that had already
     * applied its mutations would burn a recovery code or advance a timestep for
     * an authentication that cannot have happened, which is precisely the
     * partial commit the single-use design exists to prevent.
     */
    $attempt = auditAttempt();
    $credential = backdatedCredential();
    $before = $credential->updated_at;

    // The row is gone; the in-memory model the caller holds is not.
    DB::table('auth_attempts')->where('id', $attempt->id)->delete();

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 12_345),
    );

    $credential->refresh();

    expect($outcome)->toBe(TransitionOutcome::ConcurrentModification)
        ->and($credential->last_used_timestep)->toBeNull()
        ->and($credential->last_used_at)->toBeNull()
        ->and($credential->updated_at->equalTo($before))->toBeTrue()
        // And no attempt was recreated on the way past.
        ->and(AuthAttempt::query()->count())->toBe(0);
});
