<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @param array<string, mixed> $overrides
 */
function attempt(array $overrides = []): AuthAttempt
{
    return AuthAttempt::create(array_merge([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::Initiated,
        'version' => 1,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ], $overrides));
}

it('casts state to the kernel enum', function (): void {
    expect(AuthAttempt::findOrFail(attempt()->id)->state)->toBe(AttemptState::Initiated);
});

it('starts at version 1 and requires a unique handle', function (): void {
    $first = attempt();

    expect($first->version)->toBe(1);

    attempt(['handle' => $first->handle]);
})->throws(\Illuminate\Database\QueryException::class);

it('stores satisfied factors as an array', function (): void {
    $a = attempt(['satisfied_factors' => [['factor_id' => 'password', 'credential_id' => '7']]]);

    expect(AuthAttempt::findOrFail($a->id)->satisfied_factors)
        ->toBe([['factor_id' => 'password', 'credential_id' => '7']]);
});

it('never stores a challenge code in plaintext', function (): void {
    $challenge = AuthChallenge::create([
        'attempt_id' => attempt()->id,
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', '123456'),
        'expires_at' => now()->addMinutes(2),
    ]);

    $fresh = AuthChallenge::findOrFail($challenge->id);

    expect($fresh->code_hash)->toBe(hash('sha256', '123456'))
        ->and($fresh->getAttributes())->not->toHaveKey('code');
});

it('starts a challenge unconsumed with a zero attempt counter', function (): void {
    $challenge = AuthChallenge::create([
        'attempt_id' => attempt()->id,
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', '123456'),
        'expires_at' => now()->addMinutes(2),
    ]);

    $fresh = AuthChallenge::findOrFail($challenge->id);

    expect($fresh->consumed_at)->toBeNull()
        ->and($fresh->attempts)->toBe(0);
});

it('deletes challenges when their attempt is deleted', function (): void {
    $a = attempt();
    AuthChallenge::create([
        'attempt_id' => $a->id,
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', '123456'),
        'expires_at' => now()->addMinutes(2),
    ]);

    $a->delete();

    expect(AuthChallenge::count())->toBe(0);
});
