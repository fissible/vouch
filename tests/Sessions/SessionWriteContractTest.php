<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * The keys of the session write, which nothing asserted.
 *
 * updateOrCreate's MATCH array decides which row a login lands on. Every key in
 * it is load-bearing in a way a returned value cannot show, and the failure
 * modes are not subtle: drop `revoked_at` and a login revives a session an
 * administrator revoked; drop `user_id` and it lands on somebody else's row.
 */

function writeFactor(): SatisfiedFactor
{
    return new SatisfiedFactor('password', '7', FactorKind::Knowledge, FactorStrength::Knowledge,
        false, false, false, null, new DateTimeImmutable('2026-08-14T10:00:00+00:00'));
}

function writeSuccess(int $userId = 7, string $acr = 'aal1'): AuthSuccess
{
    return new AuthSuccess($userId, [writeFactor()], AssuranceFacts::fromFactors([writeFactor()]), $acr, 'ignored');
}

it('never revives a revoked session row', function (): void {
    /*
     * `revoked_at => null` in the match array is what stops this. Without it the
     * login matches the revoked row and updates it -- so "all other sessions
     * invalidated on password change" is undone by the next login, and a session
     * an administrator deliberately killed comes back carrying its old id.
     */
    session()->start();

    $revoked = AuthSession::create([
        'session_binding' => str_repeat('r', 64),
        'user_id' => 7,
        'amr' => ['password'],
        'revoked_at' => now(),
        'revoked_reason' => RevokedReason::AdminRevoked,
    ]);

    app(SessionLifecycle::class)->establish(writeSuccess());

    expect($revoked->refresh()->revoked_at)->not->toBeNull()
        ->and($revoked->revoked_reason)->toBe(RevokedReason::AdminRevoked)
        ->and($revoked->session_binding)->toBe(str_repeat('r', 64))
        // A NEW row for the live session, not the revived one.
        ->and(AuthSession::whereNull('revoked_at')->count())->toBe(1);
});

it('never lands a login on another user session row', function (): void {
    // `user_id` in the match array. Without it, updateOrCreate matches the first
    // unrevoked row it finds -- whoever owns it.
    session()->start();

    $other = AuthSession::create([
        'session_binding' => str_repeat('o', 64),
        'user_id' => 8,
        'amr' => ['password'],
    ]);

    app(SessionLifecycle::class)->establish(writeSuccess(userId: 7));

    expect($other->refresh()->session_binding)->toBe(str_repeat('o', 64))
        ->and($other->user_id)->toBe(8)
        ->and(AuthSession::where('user_id', 7)->count())->toBe(1);
});

it('clears the recovery grace deadline when a real session is established', function (): void {
    /*
     * A user in recovery grace who then authenticates properly must come out of
     * grace. Left set, the row is a full session that still answers to the grace
     * predicate -- simultaneously authenticated and a constrained capability,
     * which no code downstream is written to expect.
     */
    session()->start();

    AuthSession::create([
        'session_binding' => str_repeat('g', 64),
        'user_id' => 7,
        'amr' => ['recovery_code'],
        'recovery_grace_expires_at' => now()->addMinutes(15),
    ]);

    app(SessionLifecycle::class)->establish(writeSuccess());

    expect(AuthSession::whereNull('revoked_at')->firstOrFail()->recovery_grace_expires_at)->toBeNull();
});

it('records both the time and the reason when revoking siblings', function (): void {
    /*
     * `revoked_at` is the mechanism -- ValidatesVouchSession reads it -- and
     * `revoked_reason` is the audit record. Losing the first means the sibling
     * sessions keep working while the code reports how many it revoked; losing
     * the second means a revocation nobody can explain later.
     */
    session()->start();
    app(SessionLifecycle::class)->establish(writeSuccess());
    $keep = AuthSession::whereNull('revoked_at')->firstOrFail()->session_binding;

    AuthSession::create(['session_binding' => str_repeat('s', 64), 'user_id' => 7, 'amr' => ['password']]);

    app(SessionLifecycle::class)->revokeSiblings(7, $keep, RevokedReason::PasswordChanged);

    $sibling = AuthSession::where('session_binding', str_repeat('s', 64))->firstOrFail();

    expect($sibling->revoked_at)->not->toBeNull()
        ->and($sibling->revoked_reason)->toBe(RevokedReason::PasswordChanged);
});

it('refuses to derive a binding without an application key', function (): void {
    /*
     * The HMAC key. A blank APP_KEY -- what a set-but-empty environment variable
     * produces -- would key the binding with the empty string, making every
     * binding derivable by anyone who knows the algorithm.
     */
    config(['app.key' => '']);

    expect(fn (): string => SessionBinding::for('host-1', BindingDomain::Session))
        ->toThrow(RuntimeException::class, 'Vouch requires APP_KEY to be set');
});
