<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('never stores the raw host session id', function (): void {
    $hostSessionId = 'the-raw-bearer-session-id';

    $binding = SessionBinding::for($hostSessionId, BindingDomain::Session);

    expect($binding)->not->toContain($hostSessionId)
        ->and($binding)->toHaveLength(64);
});

it('produces a stable binding for the same session id', function (): void {
    expect(SessionBinding::for('abc', BindingDomain::Session))->toBe(SessionBinding::for('abc', BindingDomain::Session));
});

it('produces different bindings for different session ids', function (): void {
    expect(SessionBinding::for('abc', BindingDomain::Session))->not->toBe(SessionBinding::for('abd', BindingDomain::Session));
});

it('produces a different binding when APP_KEY changes', function (): void {
    // Pins a documented consequence rather than an accident: rotating APP_KEY
    // invalidates every session, which is already true of Laravel's encrypted
    // cookies. If someone swaps the HMAC for an unkeyed hash for convenience,
    // this fails and asks why.
    $before = SessionBinding::for('abc', BindingDomain::Session);

    config(['app.key' => 'base64:' . base64_encode(random_bytes(32))]);

    expect(SessionBinding::for('abc', BindingDomain::Session))->not->toBe($before);
});

it('refuses to derive a binding with no APP_KEY', function (): void {
    config(['app.key' => null]);

    SessionBinding::for('abc', BindingDomain::Session);
})->throws(RuntimeException::class);

it('never writes the raw session id to the database', function (): void {
    AuthSession::create([
        'session_binding' => SessionBinding::for('raw-id-must-not-appear', BindingDomain::Session),
        'user_id' => 1,
        'amr' => ['password'],
    ]);

    $stored = DB::table('auth_sessions')->value('session_binding');

    expect($stored)->not->toContain('raw-id-must-not-appear');
});

it('permits only one row per session binding', function (): void {
    $binding = SessionBinding::for('abc', BindingDomain::Session);

    AuthSession::create(['session_binding' => $binding, 'user_id' => 1, 'amr' => ['password']]);
    AuthSession::create(['session_binding' => $binding, 'user_id' => 2, 'amr' => ['password']]);
})->throws(\Illuminate\Database\QueryException::class);

it('rotates by updating the binding in place rather than adding a row', function (): void {
    $session = AuthSession::create([
        'session_binding' => SessionBinding::for('old-id', BindingDomain::Session),
        'user_id' => 1,
        'amr' => ['recovery_code'],
        'recovery_grace_expires_at' => now()->addMinutes(15),
    ]);

    $session->update([
        'session_binding' => SessionBinding::for('new-id', BindingDomain::Session),
        'amr' => ['totp'],
        'recovery_grace_expires_at' => null,
    ]);

    $fresh = AuthSession::findOrFail($session->id);

    expect(AuthSession::count())->toBe(1)
        ->and($fresh->amr)->toBe(['totp'])
        ->and($fresh->recovery_grace_expires_at)->toBeNull();
});

it('reports recovery grace by the marker, not by inspecting the amr', function (): void {
    // Reads the timestamp so an empty or malformed amr cannot be mistaken for
    // a normal session. The failure direction matters; this one fails closed.
    $grace = AuthSession::create([
        'session_binding' => SessionBinding::for('grace', BindingDomain::Session),
        'user_id' => 1,
        'amr' => ['recovery_code'],
        'recovery_grace_expires_at' => now()->addMinutes(15),
    ]);

    $normal = AuthSession::create([
        'session_binding' => SessionBinding::for('normal', BindingDomain::Session),
        'user_id' => 1,
        'amr' => ['password', 'totp'],
    ]);

    expect($grace->isRecoveryGrace())->toBeTrue()
        ->and($normal->isRecoveryGrace())->toBeFalse();
});

it('constrains the revocation reason to the known set', function (): void {
    $session = AuthSession::create([
        'session_binding' => SessionBinding::for('abc', BindingDomain::Session),
        'user_id' => 1,
        'amr' => ['password'],
    ]);

    $session->update([
        'revoked_at' => now(),
        'revoked_reason' => RevokedReason::PasswordChanged,
    ]);

    expect(AuthSession::findOrFail($session->id)->revoked_reason)
        ->toBe(RevokedReason::PasswordChanged);
});

it('lists every revocation reason exactly once', function (): void {
    expect(array_map(fn (RevokedReason $r): string => $r->value, RevokedReason::cases()))
        ->toBe([
            'logout',
            'grace_expired',
            'credential_changed',
            'password_changed',
            'admin_revoked',
            'superseded',
        ]);
});
