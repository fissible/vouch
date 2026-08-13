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
    return new SatisfiedFactor($id, '7', FactorKind::Knowledge, FactorStrength::Knowledge,
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
    // 2.1 established rotate-in-place; a second row would orphan the first
    // binding and leave a session nothing can revoke.
    session()->start();
    lifecycle()->establish(lifecycleSuccess());
    lifecycle()->establish(lifecycleSuccess(acr: 'aal2'));

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
