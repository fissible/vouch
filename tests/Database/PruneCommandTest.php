<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;

uses(RefreshDatabase::class);

it('deletes expired attempts and keeps live ones', function (): void {
    AuthAttempt::create([
        'handle' => 'expired', 'state' => AttemptState::Initiated, 'version' => 1,
        'expires_at' => now()->subMinute(),
    ]);
    AuthAttempt::create([
        'handle' => 'live', 'state' => AttemptState::Initiated, 'version' => 1,
        'expires_at' => now()->addMinute(),
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    expect(AuthAttempt::pluck('handle')->all())->toBe(['live']);
});

it('reaps challenges belonging to pruned attempts', function (): void {
    $expired = AuthAttempt::create([
        'handle' => 'expired', 'state' => AttemptState::Initiated, 'version' => 1,
        'expires_at' => now()->subMinute(),
    ]);
    AuthChallenge::create([
        'attempt_id' => $expired->id,
        'factor_type' => 'password',
        'code_hash' => hash('sha256', '123456'),
        'expires_at' => now()->addMinutes(2),
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    expect(AuthChallenge::count())->toBe(0);
});

it('deletes revoked sessions past the retention window and keeps recent ones', function (): void {
    config(['vouch.sessions.revocation_retention_days' => 30]);

    AuthSession::create([
        'session_binding' => SessionBinding::for('old'), 'user_id' => 1, 'amr' => ['password'],
        'revoked_at' => now()->subDays(31), 'revoked_reason' => RevokedReason::Logout,
    ]);
    AuthSession::create([
        'session_binding' => SessionBinding::for('recent'), 'user_id' => 1, 'amr' => ['password'],
        'revoked_at' => now()->subDays(29), 'revoked_reason' => RevokedReason::Logout,
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    expect(AuthSession::count())->toBe(1)
        ->and(AuthSession::firstOrFail()->session_binding)->toBe(SessionBinding::for('recent'));
});

it('never deletes a live session', function (): void {
    AuthSession::create([
        'session_binding' => SessionBinding::for('live'), 'user_id' => 1, 'amr' => ['password'],
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    expect(AuthSession::count())->toBe(1);
});

it('does not delete an unrevoked session whose grace has expired', function (): void {
    // Grace expiry is enforced per-request, never by the sweep. If the sweep
    // deleted expired-grace rows, a request arriving between expiry and the
    // sweep would find no row and could be treated as an ordinary
    // unauthenticated visitor rather than a rejected grace session — and the
    // sweep would have quietly become the enforcement mechanism it must
    // never be.
    AuthSession::create([
        'session_binding' => SessionBinding::for('grace'), 'user_id' => 1,
        'amr' => ['recovery_code'],
        'recovery_grace_expires_at' => now()->subHour(),
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    expect(AuthSession::count())->toBe(1);
});
