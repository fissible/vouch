<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function pruneOutbox(string $status, DateTimeInterface $expiresAt): AuthChallengeOutbox
{
    $attempt = AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'bound_context' => str_repeat('o', 64),
        'expires_at' => now()->addHour(),
    ]);
    $challenge = AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'password',
        'code_hash' => 'not-a-live-code',
        'expires_at' => $expiresAt,
    ]);

    return AuthChallengeOutbox::create([
        'opaque_id' => bin2hex(random_bytes(32)),
        'challenge_id' => $challenge->id,
        'payload' => $status === OtpOutboxStatus::Delivered->value
            ? null
            : ['target' => null, 'code' => 'live-prune-secret', 'decoy' => true],
        'status' => $status,
        'expires_at' => $expiresAt,
        'delivered_at' => $status === OtpOutboxStatus::Delivered->value ? now() : null,
        'undeliverable_at' => $status === OtpOutboxStatus::Undeliverable->value ? now() : null,
    ]);
}

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
        'session_binding' => SessionBinding::for('old', BindingDomain::Session), 'user_id' => 1, 'amr' => ['password'],
        'revoked_at' => now()->subDays(31), 'revoked_reason' => RevokedReason::Logout,
    ]);
    AuthSession::create([
        'session_binding' => SessionBinding::for('recent', BindingDomain::Session), 'user_id' => 1, 'amr' => ['password'],
        'revoked_at' => now()->subDays(29), 'revoked_reason' => RevokedReason::Logout,
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    expect(AuthSession::count())->toBe(1)
        ->and(AuthSession::firstOrFail()->session_binding)->toBe(SessionBinding::for('recent', BindingDomain::Session));
});

it('accepts the minimum session retention and refuses zero', function (): void {
    config(['vouch.sessions.revocation_retention_days' => 1]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    config(['vouch.sessions.revocation_retention_days' => 0]);

    expect(Artisan::call('vouch:prune'))->toBe(1)
        ->and(Artisan::output())->toContain(
            'Configuration "vouch.sessions.revocation_retention_days" must be at least 1.',
        );
});

it('never deletes a live session', function (): void {
    AuthSession::create([
        'session_binding' => SessionBinding::for('live', BindingDomain::Session), 'user_id' => 1, 'amr' => ['password'],
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
        'session_binding' => SessionBinding::for('grace', BindingDomain::Session), 'user_id' => 1,
        'amr' => ['recovery_code'],
        'recovery_grace_expires_at' => now()->subHour(),
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    expect(AuthSession::count())->toBe(1);
});

it('prunes scalar and tuple state at their database-clock boundaries without deleting live locks or persistent parents', function (): void {
    $now = app(DatabaseTime::class)->current();
    $counterOld = DB::table('auth_throttle_counters')->insertGetId([
        'dimension' => 'identifier',
        'subject_digest' => str_repeat('a', 64),
        'window_started_at' => $now,
        'count' => 1,
        'created_at' => $now,
        'updated_at' => $now->sub(new DateInterval('PT86400S')),
    ]);
    $counterLive = DB::table('auth_throttle_counters')->insertGetId([
        'dimension' => 'identifier',
        'subject_digest' => str_repeat('b', 64),
        'window_started_at' => $now,
        'count' => 1,
        'created_at' => $now,
        'updated_at' => $now->sub(new DateInterval('PT80000S')),
    ]);
    $lockOld = DB::table('auth_throttle_locks')->insertGetId([
        'subject_digest' => str_repeat('c', 64),
        'locked_until' => $now->sub(new DateInterval('PT1S')),
        'created_at' => $now,
        'updated_at' => $now->sub(new DateInterval('PT86400S')),
    ]);
    $lockActive = DB::table('auth_throttle_locks')->insertGetId([
        'subject_digest' => str_repeat('d', 64),
        'locked_until' => $now->add(new DateInterval('PT60S')),
        'created_at' => $now,
        'updated_at' => $now->sub(new DateInterval('PT86400S')),
    ]);
    $parent = DB::table('auth_throttle_ip_windows')->insertGetId([
        'dimension' => 'ipv4',
        'ip_digest' => str_repeat('e', 64),
        'window_started_at' => $now,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $tupleOld = DB::table('auth_throttle_tuples')->insertGetId([
        'ip_window_id' => $parent,
        'window_started_at' => $now->sub(new DateInterval('PT900S')),
        'tuple_digest' => str_repeat('f', 64),
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $tupleLive = DB::table('auth_throttle_tuples')->insertGetId([
        'ip_window_id' => $parent,
        'window_started_at' => $now->sub(new DateInterval('PT800S')),
        'tuple_digest' => str_repeat('1', 64),
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    DB::table('auth_enrollment_locks')->insert(['user_id' => 7, 'type' => 'email_otp']);

    expect(Artisan::call('vouch:prune'))->toBe(0)
        ->and(DB::table('auth_throttle_counters')->where('id', $counterOld)->exists())->toBeFalse()
        ->and(DB::table('auth_throttle_counters')->where('id', $counterLive)->exists())->toBeTrue()
        ->and(DB::table('auth_throttle_locks')->where('id', $lockOld)->exists())->toBeFalse()
        ->and(DB::table('auth_throttle_locks')->where('id', $lockActive)->exists())->toBeTrue()
        ->and(DB::table('auth_throttle_tuples')->where('id', $tupleOld)->exists())->toBeFalse()
        ->and(DB::table('auth_throttle_tuples')->where('id', $tupleLive)->exists())->toBeTrue()
        ->and(DB::table('auth_throttle_ip_windows')->where('id', $parent)->exists())->toBeTrue()
        ->and(DB::table('auth_enrollment_locks')->count())->toBe(1);
});

it('returns two only after committing every deletion and exact expired-undelivered counts', function (): void {
    $databaseNow = app(DatabaseTime::class)->current();
    $expiredAttempt = AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::Initiated,
        'version' => 1,
        'expires_at' => now()->subMinute(),
    ]);
    AuthChallenge::create([
        'attempt_id' => $expiredAttempt->id,
        'factor_type' => 'password',
        'code_hash' => 'expired-attempt-challenge',
        'expires_at' => now()->subMinute(),
    ]);
    AuthSession::create([
        'session_binding' => SessionBinding::for('status-two', BindingDomain::Session),
        'user_id' => 1,
        'amr' => ['password'],
        'revoked_at' => now()->subDays(31),
        'revoked_reason' => RevokedReason::Logout,
    ]);
    pruneOutbox(OtpOutboxStatus::Delivered->value, $databaseNow);
    pruneOutbox(OtpOutboxStatus::Pending->value, $databaseNow);
    pruneOutbox(OtpOutboxStatus::Undeliverable->value, $databaseNow);
    $live = pruneOutbox(OtpOutboxStatus::Pending->value, now()->addMinute());
    DB::table('auth_throttle_counters')->insert([
        'dimension' => 'identifier',
        'subject_digest' => str_repeat('2', 64),
        'window_started_at' => $databaseNow,
        'count' => 1,
        'created_at' => $databaseNow,
        'updated_at' => $databaseNow->sub(new DateInterval('PT86400S')),
    ]);
    DB::table('auth_throttle_locks')->insert([
        'subject_digest' => str_repeat('3', 64),
        'locked_until' => $databaseNow->sub(new DateInterval('PT1S')),
        'created_at' => $databaseNow,
        'updated_at' => $databaseNow->sub(new DateInterval('PT86400S')),
    ]);
    $parent = DB::table('auth_throttle_ip_windows')->insertGetId([
        'dimension' => 'ipv4',
        'ip_digest' => str_repeat('4', 64),
        'window_started_at' => $databaseNow,
        'created_at' => $databaseNow,
        'updated_at' => $databaseNow,
    ]);
    DB::table('auth_throttle_tuples')->insert([
        'ip_window_id' => $parent,
        'window_started_at' => $databaseNow->sub(new DateInterval('PT900S')),
        'tuple_digest' => str_repeat('5', 64),
        'created_at' => $databaseNow,
        'updated_at' => $databaseNow,
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(2);

    $output = Artisan::output();

    expect($output)->toContain('1 attempt(s)')
        ->and($output)->toContain('1 challenge(s)')
        ->and($output)->toContain('1 revoked session(s)')
        ->and($output)->toContain('1 throttle counter(s)')
        ->and($output)->toContain('1 expired identifier lock(s)')
        ->and($output)->toContain('1 tuple marker(s)')
        ->and($output)->toContain('1 delivered OTP outbox row(s)')
        ->and($output)->toContain('2 expired-undelivered OTP outbox row(s)')
        ->and($output)->toContain('Found 2 expired undelivered OTP delivery row(s)')
        ->and(AuthAttempt::query()->whereKey($expiredAttempt->id)->exists())->toBeFalse()
        ->and(AuthSession::query()->count())->toBe(0)
        ->and(DB::table('auth_throttle_counters')->count())->toBe(0)
        ->and(DB::table('auth_throttle_locks')->count())->toBe(0)
        ->and(DB::table('auth_throttle_tuples')->count())->toBe(0)
        ->and(DB::table('auth_throttle_ip_windows')->where('id', $parent)->exists())->toBeTrue()
        ->and(AuthChallengeOutbox::query()->whereKey($live->id)->exists())->toBeTrue()
        ->and(AuthChallengeOutbox::query()->count())->toBe(1);
});

it('returns zero after pruning delivered expiry with no worker-health finding', function (): void {
    pruneOutbox(OtpOutboxStatus::Delivered->value, now()->subSecond());

    $status = Artisan::call('vouch:prune');
    $output = Artisan::output();

    expect($status)->toBe(0)
        ->and($output)->toContain('1 delivered OTP outbox row(s)')
        ->and($output)->toContain('0 expired-undelivered OTP outbox row(s)')
        ->and($output)->not->toContain('route this alert to delivery-worker health');
});

it('removes encrypted OTP material at the exact database deadline regardless of scalar retention', function (): void {
    $deadline = app(DatabaseTime::class)->current();
    $outbox = pruneOutbox(OtpOutboxStatus::Pending->value, $deadline);
    $rawPayload = DB::table('auth_challenge_outbox')
        ->where('id', $outbox->id)
        ->value('payload');

    config()->set('vouch.throttle.retention_seconds', 172_800);
    app()->forgetInstance(\Fissible\Vouch\Throttle\ThrottleConfiguration::class);

    expect($rawPayload)->toBeString()
        ->and($rawPayload)->not->toContain('live-prune-secret')
        ->and(Artisan::call('vouch:prune'))->toBe(2)
        ->and(AuthChallengeOutbox::query()->whereKey($outbox->id)->exists())->toBeFalse();
});

it('rolls back earlier deletions on prune failure without emitting a delivery-health finding', function (): void {
    $expired = AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::Initiated,
        'version' => 1,
        'expires_at' => now()->subMinute(),
    ]);
    $outbox = pruneOutbox(OtpOutboxStatus::Pending->value, now()->subSecond());
    $injected = false;
    DB::connection()->beforeExecuting(static function (string $query) use (&$injected): void {
        if (str_starts_with(strtolower($query), 'delete')
            && str_contains($query, 'auth_sessions')) {
            $injected = true;

            throw new RuntimeException('injected failure after earlier prune deletes');
        }
    });

    $status = Artisan::call('vouch:prune');
    $output = Artisan::output();

    expect($status)->toBe(1)
        ->and($injected)->toBeTrue()
        ->and($output)->toContain('Vouch prune failed')
        ->and($output)->toContain('injected failure after earlier prune deletes')
        ->and($output)->not->toContain('route this alert to delivery-worker health')
        ->and(AuthAttempt::query()->whereKey($expired->id)->exists())->toBeTrue()
        ->and(AuthChallengeOutbox::query()->whereKey($outbox->id)->exists())->toBeTrue();
});
