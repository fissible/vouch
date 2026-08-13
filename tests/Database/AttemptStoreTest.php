<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @param array<string, mixed> $overrides
 */
function storeAttempt(array $overrides = []): AuthAttempt
{
    return AuthAttempt::create(array_merge([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::Initiated,
        'version' => 1,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ], $overrides));
}

function liveChallenge(AuthAttempt $attempt): AuthChallenge
{
    return AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'password',
        'code_hash' => hash('sha256', '123456'),
        'expires_at' => now()->addMinutes(2),
    ]);
}

it('advances a legal transition and increments the version', function (): void {
    $attempt = storeAttempt();

    $outcome = app(AttemptStore::class)->transition($attempt, AttemptState::Identified);

    $fresh = AuthAttempt::findOrFail($attempt->id);

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and($fresh->state)->toBe(AttemptState::Identified)
        ->and($fresh->version)->toBe(2);
});

it('refuses an illegal transition without writing', function (): void {
    $attempt = storeAttempt();

    $outcome = app(AttemptStore::class)->transition($attempt, AttemptState::Authenticated);

    $fresh = AuthAttempt::findOrFail($attempt->id);

    expect($outcome)->toBe(TransitionOutcome::IllegalTransition)
        ->and($fresh->state)->toBe(AttemptState::Initiated)
        ->and($fresh->version)->toBe(1);
});

it('refuses a transition on an expired attempt', function (): void {
    $attempt = storeAttempt(['expires_at' => now()->subSecond()]);

    expect(app(AttemptStore::class)->transition($attempt, AttemptState::Identified))
        ->toBe(TransitionOutcome::Expired);
});

it('refuses a transition presented from a different bound context', function (): void {
    $attempt = storeAttempt();
    $attempt->bound_context = 'sess-2';

    expect(app(AttemptStore::class)->transition($attempt, AttemptState::Identified))
        ->toBe(TransitionOutcome::ContextMismatch);
});

it('consumes a challenge and advances in one operation', function (): void {
    $attempt = storeAttempt(['state' => AttemptState::FactorPending, 'version' => 3]);
    $challenge = liveChallenge($attempt);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challenge->id, $attempt->id),
    );

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and(AuthChallenge::findOrFail($challenge->id)->consumed_at)->not->toBeNull()
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(4);
});

it('refuses to advance on an already-consumed challenge and rolls back', function (): void {
    $attempt = storeAttempt(['state' => AttemptState::FactorPending, 'version' => 3]);
    $challenge = liveChallenge($attempt);
    $challenge->update(['consumed_at' => now()]);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challenge->id, $attempt->id),
    );

    $fresh = AuthAttempt::findOrFail($attempt->id);

    expect($outcome)->toBe(TransitionOutcome::ChallengeAlreadyConsumed)
        ->and($fresh->state)->toBe(AttemptState::FactorPending)
        ->and($fresh->version)->toBe(3);
});

it('refuses to advance on an expired challenge and rolls back', function (): void {
    $attempt = storeAttempt(['state' => AttemptState::FactorPending, 'version' => 3]);
    $challenge = liveChallenge($attempt);
    $challenge->update(['expires_at' => now()->subSecond()]);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challenge->id, $attempt->id),
    );

    expect($outcome)->toBe(TransitionOutcome::ChallengeAlreadyConsumed)
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(3);
});

it('leaves an expired challenge unconsumed when it refuses', function (): void {
    // The refusal must not burn the code as a side effect: that would be a
    // denial of service against a user whose request merely arrived late.
    $attempt = storeAttempt(['state' => AttemptState::FactorPending, 'version' => 3]);
    $challenge = liveChallenge($attempt);
    $challenge->update(['expires_at' => now()->subSecond()]);

    app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challenge->id, $attempt->id),
    );

    expect(AuthChallenge::findOrFail($challenge->id)->consumed_at)->toBeNull();
});

it('refuses a transition whose version is stale', function (): void {
    $attempt = storeAttempt();

    // Someone else advanced it since this instance was read.
    AuthAttempt::whereKey($attempt->id)->update(['version' => 2]);

    expect(app(AttemptStore::class)->transition($attempt, AttemptState::Identified))
        ->toBe(TransitionOutcome::ConcurrentModification);
});

it('does not consume a challenge when the attempt CAS loses', function (): void {
    // Ordering matters: the challenge update runs first, so a lost CAS on the
    // attempt must roll the consumption back rather than leave it spent.
    $attempt = storeAttempt(['state' => AttemptState::FactorPending, 'version' => 3]);
    $challenge = liveChallenge($attempt);

    AuthAttempt::whereKey($attempt->id)->update(['version' => 4]);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challenge->id, $attempt->id),
    );

    expect($outcome)->toBe(TransitionOutcome::ConcurrentModification)
        ->and(AuthChallenge::findOrFail($challenge->id)->consumed_at)->toBeNull();
});
