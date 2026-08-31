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
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function lifecycle(): SessionLifecycle
{
    return app(SessionLifecycle::class);
}

function lifecycleFactor(string $id = 'password'): SatisfiedFactor
{
    // A DISTINCT credential per factor id: the derived level counts distinct
    // credentials, so two factors sharing one credential are one authenticator.
    return new SatisfiedFactor($id, 'cred-' . $id, FactorKind::Knowledge, FactorStrength::Knowledge,
        false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'));
}

function lifecycleSuccess(int $userId = 7, string $acr = 'aal1'): AuthSuccess
{
    return new AuthSuccess(
        $userId,
        [lifecycleFactor()],
        AssuranceFacts::fromFactors([lifecycleFactor()]),
        $acr,
        'ignored',
    );
}

it('regenerates the host session and records the new binding', function (): void {
    session()->start();
    $before = session()->getId();

    lifecycle()->establish(lifecycleSuccess());

    $after = session()->getId();

    expect($after)->not->toBe($before)
        ->and(AuthSession::count())->toBe(1)
        ->and(AuthSession::firstOrFail()->session_binding)
        ->toBe(SessionBinding::for($after, BindingDomain::Session));
});

it('never stores the raw session id', function (): void {
    session()->start();
    lifecycle()->establish(lifecycleSuccess());

    expect(DB::table('auth_sessions')->value('session_binding'))->not->toBe(session()->getId());
});

it('rotates in place rather than adding a row', function (): void {
    /*
     * 2.1 established rotate-in-place; a second row would orphan the first
     * binding and leave a session nothing can revoke.
     *
     * The second establish() raises the evidence rather than passing a stronger
     * acr string. Since 2.4 Task 2a the writer DERIVES acr from the persisted
     * proof, so a hand-built AuthSuccess claiming aal2 over a single knowledge
     * factor no longer produces an aal2 row -- and should not: that fabricated
     * disagreement between the column and its evidence is the defect Task 2a
     * removes.
     */
    session()->start();
    lifecycle()->establish(lifecycleSuccess());

    $stronger = [lifecycleFactor(), lifecycleFactor('totp')];
    lifecycle()->establish(new AuthSuccess(
        7,
        $stronger,
        AssuranceFacts::fromFactors($stronger),
        'aal2',
        'ignored',
    ));

    expect(AuthSession::count())->toBe(1)
        ->and(AuthSession::firstOrFail()->acr)->toBe('aal2');
});

it('regenerates again on an assurance increase, not only at login', function (): void {
    /*
     * §7.5 requires rotation on every assurance increase. A step-up that raised
     * assurance without rotating would leave the pre-step-up session ID valid
     * at the higher level.
     */
    session()->start();
    lifecycle()->establish(lifecycleSuccess());
    $afterLogin = session()->getId();

    lifecycle()->establish(lifecycleSuccess(acr: 'aal2'));

    expect(session()->getId())->not->toBe($afterLogin)
        ->and(AuthSession::firstOrFail()->session_binding)
        ->toBe(SessionBinding::for(session()->getId(), BindingDomain::Session));
});

it('revokes sibling sessions without touching the current one', function (): void {
    session()->start();
    lifecycle()->establish(lifecycleSuccess());
    $keep = AuthSession::firstOrFail()->session_binding;

    AuthSession::create(['session_binding' => str_repeat('a', 64), 'user_id' => 7, 'amr' => ['password']]);
    AuthSession::create(['session_binding' => str_repeat('b', 64), 'user_id' => 8, 'amr' => ['password']]);

    $revoked = lifecycle()->revokeSiblings(7, $keep, RevokedReason::PasswordChanged);

    expect($revoked)->toBe(1)
        ->and(AuthSession::where('session_binding', $keep)->firstOrFail()->revoked_at)->toBeNull()
        ->and(AuthSession::where('session_binding', str_repeat('a', 64))->firstOrFail()->revoked_reason)
        ->toBe(RevokedReason::PasswordChanged)
        ->and(AuthSession::where('user_id', 8)->firstOrFail()->revoked_at)->toBeNull();
});
