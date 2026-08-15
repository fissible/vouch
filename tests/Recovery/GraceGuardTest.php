<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;

uses(RefreshDatabase::class);

function graceGuard(): GraceGuard
{
    return app(GraceGuard::class);
}

/**
 * @param  array<string, mixed>  $extra
 */
function lapsedGraceRow(string $hostSessionId, array $extra = []): AuthSession
{
    return AuthSession::create(array_merge([
        'session_binding' => SessionBinding::for($hostSessionId, BindingDomain::Session),
        'user_id' => 7,
        'amr' => ['recovery_code'],
        // Written in the past deliberately: this fixture is about what a lapsed
        // row does, not about how a live one is created.
        'recovery_grace_expires_at' => now()->subMinute(),
    ], $extra));
}

it('opens a live capability', function (): void {
    graceGuard()->start('host-1', 7);

    expect(graceGuard()->activeFor('host-1'))->toBeInstanceOf(AuthSession::class)
        ->and(AuthSession::firstOrFail()->user_id)->toBe(7)
        ->and(AuthSession::firstOrFail()->amr)->toBe(['recovery_code']);
});

it('stamps the row it creates, from the database clock', function (): void {
    /*
     * `$table->timestamps()` is nullable, so dropping either stamp from the
     * insert leaves the row perfectly usable and every other grace assertion
     * green — while `AuthSession` declares both as non-null `Carbon`. A model
     * whose declared type is contradicted by its own writer is a defect that
     * only surfaces at the reader.
     *
     * Asserted as instances rather than values: what matters is that the write
     * path sets them at all. That they come from the DATABASE clock, not the
     * application clock, is pinned separately by the expiry test below — the
     * same authority the deadline uses.
     */
    graceGuard()->start('host-stamped', 7);

    $session = AuthSession::firstOrFail();

    expect($session->created_at)->toBeInstanceOf(Carbon::class)
        ->and($session->updated_at)->toBeInstanceOf(Carbon::class);
});

it('never stores the raw host session id', function (): void {
    graceGuard()->start('host-1', 7);

    expect(AuthSession::firstOrFail()->session_binding)->not->toContain('host-1');
});

it('does not resolve an expired capability', function (): void {
    lapsedGraceRow('host-1');

    expect(graceGuard()->activeFor('host-1'))->toBeNull();
});

it('does not resolve a revoked capability', function (): void {
    lapsedGraceRow('host-1', [
        'recovery_grace_expires_at' => now()->addMinutes(15),
        'revoked_at' => now(),
        'revoked_reason' => RevokedReason::AdminRevoked,
    ]);

    expect(graceGuard()->activeFor('host-1'))->toBeNull();
});

it('decides expiry by the database clock, not the application clock', function (): void {
    /*
     * The control that matters. Without it the predicate could be rewritten as
     * a PHP comparison and every other grace test would stay green -- exactly
     * how 2.2's TOTP tests passed while real time sat before a frozen expiry.
     */
    graceGuard()->start('host-1', 7);

    // Move the application clock far past the deadline. The database clock has
    // not moved, so the row is still live.
    Carbon::setTestNow(now()->addHours(2));

    expect(graceGuard()->activeFor('host-1'))->toBeInstanceOf(AuthSession::class);
});

it('marks a lapsed row grace_expired', function (): void {
    lapsedGraceRow('host-1');

    graceGuard()->expireIfLapsed('host-1');

    $row = AuthSession::firstOrFail();

    expect($row->revoked_reason)->toBe(RevokedReason::GraceExpired)
        ->and($row->revoked_at)->not->toBeNull();
});

it('leaves a live row alone', function (): void {
    graceGuard()->start('host-1', 7);

    graceGuard()->expireIfLapsed('host-1');

    expect(AuthSession::firstOrFail()->revoked_at)->toBeNull();
});

it('never overwrites an existing revocation reason', function (): void {
    /*
     * Audit integrity. The session is destroyed and grace routes refuse either
     * way, so the recorded cause is the ONLY thing distinguishing a deliberate
     * revocation from an ordinary lapse -- and only this test protects it.
     * Without the guard the system files a false audit entry about itself.
     */
    lapsedGraceRow('host-1', [
        'revoked_at' => now()->subMinutes(5),
        'revoked_reason' => RevokedReason::AdminRevoked,
    ]);

    graceGuard()->expireIfLapsed('host-1');

    expect(AuthSession::firstOrFail()->revoked_reason)->toBe(RevokedReason::AdminRevoked);
});
