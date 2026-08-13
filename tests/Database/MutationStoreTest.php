<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\ConflictingMutations;
use Fissible\Vouch\Attempts\MisdirectedMutation;
use Fissible\Vouch\Attempts\Mutations\AdvanceCredentialTimestep;
use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Attempts\Mutations\DisableCredential;
use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Attempts\UnknownMutation;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @param array<string, mixed> $overrides
 */
function mutableAttempt(array $overrides = []): AuthAttempt
{
    return AuthAttempt::create(array_merge([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => 7,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ], $overrides));
}

function recoveryCredential(): AuthCredential
{
    return AuthCredential::create([
        'user_id' => 7,
        'type' => 'recovery_code',
        'secret' => 'digest',
        'strength' => 'recovery',
    ]);
}

function totpCredential(?int $timestep = null): AuthCredential
{
    return AuthCredential::create([
        'user_id' => 7,
        'type' => 'totp',
        'secret' => 'JBSWY3DPEHPK3PXP',
        'strength' => 'possession',
        'last_used_timestep' => $timestep,
    ]);
}

it('disables a credential atomically with the transition', function (): void {
    $attempt = mutableAttempt();
    $credential = recoveryCredential();

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new DisableCredential($credential->id),
    );

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and(AuthCredential::findOrFail($credential->id)->disabled_at)->not->toBeNull()
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(2);
});

it('refuses to disable an already-disabled credential and advances nothing', function (): void {
    $attempt = mutableAttempt();
    $credential = recoveryCredential();
    $credential->update(['disabled_at' => now()]);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new DisableCredential($credential->id),
    );

    expect($outcome)->toBe(TransitionOutcome::CredentialAlreadyConsumed)
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(1);
});

it('rolls the credential disable back when the transition loses', function (): void {
    /*
     * The most valuable test here, and the reason single-use state belongs to
     * the store at all: without the rollback, a lost race burns a recovery code
     * while the user stays unauthenticated. That is a denial of service against
     * a legitimate user, and it is invisible to any test that only asserts on
     * the returned outcome.
     */
    $attempt = mutableAttempt();
    $credential = recoveryCredential();

    // Stale version: the caller's in-memory attempt lost the CAS.
    $stale = AuthAttempt::findOrFail($attempt->id);
    AuthAttempt::where('id', $attempt->id)->update(['version' => 5]);

    $outcome = app(AttemptStore::class)->transition(
        $stale,
        AttemptState::FactorSatisfied,
        new DisableCredential($credential->id),
    );

    expect($outcome)->toBe(TransitionOutcome::ConcurrentModification)
        ->and(AuthCredential::findOrFail($credential->id)->disabled_at)->toBeNull();
});

it('advances a timestep forward', function (): void {
    $attempt = mutableAttempt();
    $credential = totpCredential(timestep: 100);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 101),
    );

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and(AuthCredential::findOrFail($credential->id)->last_used_timestep)->toBe(101);
});

it('refuses to replay a timestep already used', function (): void {
    $attempt = mutableAttempt();
    $credential = totpCredential(timestep: 100);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 100),
    );

    expect($outcome)->toBe(TransitionOutcome::TimestepReplay)
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(1);
});

it('refuses to move a timestep backwards', function (): void {
    // A clock that jumped back must not reopen an already-spent window.
    $attempt = mutableAttempt();
    $credential = totpCredential(timestep: 100);

    expect(app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 99),
    ))->toBe(TransitionOutcome::TimestepReplay);
});

it('accepts the first timestep when none has been recorded', function (): void {
    $attempt = mutableAttempt();
    $credential = totpCredential(timestep: null);

    expect(app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 100),
    ))->toBe(TransitionOutcome::Succeeded);
});

it('applies several mutations for different targets in one transaction', function (): void {
    $attempt = mutableAttempt();
    $challenge = AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'password',
        'code_hash' => 'digest',
        'expires_at' => now()->addMinutes(2),
    ]);
    $credential = recoveryCredential();

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challenge->id, $attempt->id),
        new DisableCredential($credential->id),
    );

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and(AuthChallenge::findOrFail($challenge->id)->consumed_at)->not->toBeNull()
        ->and(AuthCredential::findOrFail($credential->id)->disabled_at)->not->toBeNull();
});

it('rolls every mutation back when one of them refuses', function (): void {
    $attempt = mutableAttempt();
    $challenge = AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'password',
        'code_hash' => 'digest',
        'expires_at' => now()->addMinutes(2),
    ]);
    $spent = recoveryCredential();
    $spent->update(['disabled_at' => now()]);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challenge->id, $attempt->id),
        new DisableCredential($spent->id),
    );

    expect($outcome)->toBe(TransitionOutcome::CredentialAlreadyConsumed)
        ->and(AuthChallenge::findOrFail($challenge->id)->consumed_at)->toBeNull();
});

it('refuses to consume a challenge that does not belong to the named attempt', function (): void {
    /*
     * Every other test in this file constructs ConsumeChallenge with the id of
     * the attempt that actually owns the challenge, so none of them exercise
     * the attempt_id conjunct in the guarded update. Delete that conjunct and
     * this is the only test that notices: the attempt being advanced (B) and
     * the attempt named on the mutation (also B) agree with each other, so the
     * pre-flight cross-check passes, but the challenge itself belongs to A.
     */
    $attemptA = mutableAttempt();
    $attemptB = mutableAttempt();
    $challengeOfA = AuthChallenge::create([
        'attempt_id' => $attemptA->id,
        'factor_type' => 'password',
        'code_hash' => 'digest',
        'expires_at' => now()->addMinutes(2),
    ]);

    $outcome = app(AttemptStore::class)->transition(
        $attemptB,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challengeOfA->id, $attemptB->id),
    );

    expect($outcome)->toBe(TransitionOutcome::ChallengeAlreadyConsumed)
        ->and(AuthChallenge::findOrFail($challengeOfA->id)->consumed_at)->toBeNull();
});

it('throws when a mutation names an attempt other than the one being advanced', function (): void {
    /*
     * ConsumeChallenge carries an attempt id specifically so this can be
     * checked. Here the mismatch is between the mutation's named attempt (A)
     * and the attempt the transition is actually advancing (B) — a different
     * failure mode than the previous test, where both agreed with each other
     * but not with the challenge's true owner. A driver that got this wrong
     * would burn A's one-time code while authenticating B.
     */
    $attemptA = mutableAttempt();
    $attemptB = mutableAttempt();
    $challengeOfA = AuthChallenge::create([
        'attempt_id' => $attemptA->id,
        'factor_type' => 'password',
        'code_hash' => 'digest',
        'expires_at' => now()->addMinutes(2),
    ]);

    app(AttemptStore::class)->transition(
        $attemptB,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challengeOfA->id, $attemptA->id),
    );
})->throws(MisdirectedMutation::class);

it('writes nothing when a misdirected mutation aborts the transition', function (): void {
    $attemptA = mutableAttempt();
    $attemptB = mutableAttempt();
    $challengeOfA = AuthChallenge::create([
        'attempt_id' => $attemptA->id,
        'factor_type' => 'password',
        'code_hash' => 'digest',
        'expires_at' => now()->addMinutes(2),
    ]);

    try {
        app(AttemptStore::class)->transition(
            $attemptB,
            AttemptState::FactorSatisfied,
            new ConsumeChallenge($challengeOfA->id, $attemptA->id),
        );
    } catch (MisdirectedMutation) {
        // expected
    }

    expect(AuthChallenge::findOrFail($challengeOfA->id)->consumed_at)->toBeNull()
        ->and(AuthAttempt::findOrFail($attemptB->id)->version)->toBe(1);
});

it('throws on two mutations sharing one target', function (): void {
    // A programming error, not a race. Applying both or arbitrarily picking one
    // would make the outcome depend on argument order.
    $attempt = mutableAttempt();
    $credential = totpCredential();

    app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new DisableCredential($credential->id),
        new AdvanceCredentialTimestep($credential->id, 101),
    );
})->throws(ConflictingMutations::class);

it('throws on a mutation type it cannot execute', function (): void {
    /*
     * PHP has no sealed interfaces, so a future driver can pass an
     * implementation the store has never heard of. Skipping it would silently
     * drop a single-use guard, which is the failure this whole design exists to
     * make impossible.
     */
    $attempt = mutableAttempt();

    $rogue = new class implements SingleUseMutation
    {
        public function target(): string
        {
            return 'rogue:1';
        }
    };

    app(AttemptStore::class)->transition($attempt, AttemptState::FactorSatisfied, $rogue);
})->throws(UnknownMutation::class);

it('writes nothing when an unknown mutation aborts the transaction', function (): void {
    $attempt = mutableAttempt();
    $credential = recoveryCredential();

    $rogue = new class implements SingleUseMutation
    {
        public function target(): string
        {
            return 'rogue:1';
        }
    };

    try {
        app(AttemptStore::class)->transition(
            $attempt,
            AttemptState::FactorSatisfied,
            new DisableCredential($credential->id),
            $rogue,
        );
    } catch (UnknownMutation) {
        // expected
    }

    expect(AuthCredential::findOrFail($credential->id)->disabled_at)->toBeNull()
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(1);
});
