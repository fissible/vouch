<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Throttle\ChallengeAttemptDecision;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function challengeAttemptStoreRow(
    int $attempts = 0,
    bool $expired = false,
    bool $consumed = false,
): int {
    $attempt = AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'bound_context' => str_repeat('c', 64),
        'expires_at' => now()->addMinutes(10),
    ]);

    return DB::table('auth_challenges')->insertGetId([
        'attempt_id' => $attempt->id,
        'factor_type' => 'email_otp',
        'code_hash' => 'not-used-by-the-store',
        'attempts' => $attempts,
        'expires_at' => $expired ? now()->subMinute() : now()->addMinutes(5),
        'consumed_at' => $consumed ? now() : null,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
}

it('atomically increments and invalidates on the configured fifth failure', function (): void {
    $store = app(AuthThrottleStore::class);
    $challengeId = challengeAttemptStoreRow();

    for ($attempt = 1; $attempt <= 4; $attempt++) {
        expect($store->recordChallengeFailure($challengeId))
            ->toBe(ChallengeAttemptDecision::Remaining);

        $challenge = AuthChallenge::findOrFail($challengeId);

        expect($challenge->attempts)->toBe($attempt)
            ->and($challenge->attempts)->toBeInt()
            ->and($challenge->consumed_at)->toBeNull();
    }

    expect($store->recordChallengeFailure($challengeId))
        ->toBe(ChallengeAttemptDecision::Invalidated);

    $invalidated = AuthChallenge::findOrFail($challengeId);

    expect($invalidated->attempts)->toBe(5)
        ->and($invalidated->consumed_at)->not->toBeNull()
        ->and($store->recordChallengeFailure($challengeId))
        ->toBe(ChallengeAttemptDecision::Consumed)
        ->and(AuthChallenge::findOrFail($challengeId)->attempts)->toBe(5);
});

it('does not charge absent expired or already-consumed challenges', function (): void {
    $store = app(AuthThrottleStore::class);
    $expired = challengeAttemptStoreRow(expired: true);
    $consumed = challengeAttemptStoreRow(consumed: true);

    expect($store->recordChallengeFailure(999_999))->toBe(ChallengeAttemptDecision::Unavailable)
        ->and($store->recordChallengeFailure($expired))->toBe(ChallengeAttemptDecision::Expired)
        ->and($store->recordChallengeFailure($consumed))->toBe(ChallengeAttemptDecision::Consumed)
        ->and(AuthChallenge::findOrFail($expired)->attempts)->toBe(0)
        ->and(AuthChallenge::findOrFail($consumed)->attempts)->toBe(0);
});

it('receives a native integer from the driver and an integer from the model cast', function (): void {
    /*
     * The SQL update is the security mechanism; the Eloquent cast is explicit
     * application shape. Current PDO drivers all return a native integer even
     * without it, and this premise runs on every engine so a driver change
     * reopens the mutation ruling loudly.
     */
    $challengeId = challengeAttemptStoreRow(attempts: 4);

    expect(DB::table('auth_challenges')->where('id', $challengeId)->value('attempts'))
        ->toBeInt()
        ->and(AuthChallenge::findOrFail($challengeId)->attempts)->toBeInt();
});

it('fails closed on a persisted negative attempt count where the engine permits one', function (): void {
    if (in_array(DB::connection()->getDriverName(), ['mysql', 'mariadb'], true)) {
        $attempt = AuthAttempt::create([
            'handle' => bin2hex(random_bytes(32)),
            'state' => AttemptState::FactorPending,
            'bound_context' => str_repeat('c', 64),
            'expires_at' => now()->addMinutes(10),
        ]);

        expect(fn (): bool => DB::table('auth_challenges')->insert([
            'attempt_id' => $attempt->id,
            'factor_type' => 'email_otp',
            'code_hash' => 'not-used-by-the-store',
            'attempts' => -1,
            'expires_at' => now()->addMinutes(5),
            'created_at' => now(),
            'updated_at' => now(),
        ]))->toThrow(\Illuminate\Database\QueryException::class);

        return;
    }

    $challengeId = challengeAttemptStoreRow(attempts: -1);

    expect(fn (): ChallengeAttemptDecision => app(AuthThrottleStore::class)
        ->recordChallengeFailure($challengeId))
        ->toThrow(RuntimeException::class, 'invalid challenge-attempt count');
});
