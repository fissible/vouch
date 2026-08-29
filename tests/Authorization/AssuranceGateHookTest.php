<?php

declare(strict_types=1);

use Fissible\Vouch\Authorization\AssuranceGateHook;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;

uses(RefreshDatabase::class);

/*
 * DEFENSE IN DEPTH ONLY (2.3d Task 5b).
 *
 * Task 5a probe 1 measured that a hook Vouch registers lands last under either
 * provider discovery order, and that a grant from an earlier hook returns
 * before it is reached. spatie's hook grants exactly when the user holds the
 * permission -- the case this map exists to constrain -- so this hook cannot
 * be the enforcement point and its tests must not pretend otherwise.
 *
 * What it must NEVER do is grant. A before hook that can return true is an
 * authorization bypass, which is far worse than the gap it closes.
 */

function gateHookSessionId(): string
{
    return substr(str_repeat('gatehooksession0', 3), 0, 40);
}

function gateHookRequest(bool $withSession = true): Request
{
    $request = Request::create('/invoices/9/approve', 'POST');

    if ($withSession) {
        $store = new Store('vouch_gate_hook', new ArraySessionHandler(120), gateHookSessionId());
        $store->start();
        $request->setLaravelSession($store);
    }

    return $request;
}

/**
 * @param  array<string, mixed>  $extra
 */
function gateHookRow(string $acr, array $extra = []): AuthSession
{
    return AuthSession::create(array_merge([
        'session_binding' => SessionBinding::for(gateHookSessionId(), BindingDomain::Session),
        'user_id' => 7,
        'amr' => ['password'],
        'acr' => $acr,
        // 2.4 Task 2a: authorization re-derives from the proof, so a fixture
        // carrying only a level proves nothing and is refused.
        'assurance_proof' => sessionProof(7, $acr),
        'weakest_satisfied_at' => now(),
    ], $extra));
}

function gateHook(): AssuranceGateHook
{
    return app(AssuranceGateHook::class);
}

function gateHookUser(int $id = 7): object
{
    $user = new Fissible\Vouch\Tests\Support\Authorization\Models\PlainProbeUser;
    $user->id = $id;

    return $user;
}

beforeEach(function (): void {
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);
});

it('defers on an ability the map does not name', function (): void {
    gateHookRow('aal0');

    expect(gateHook()->decide(gateHookUser(), 'invoices.view', gateHookRequest()))->toBeNull();
});

it('defers when the map is empty', function (): void {
    config(['vouch.assurance_requirements' => []]);
    gateHookRow('aal0');

    expect(gateHook()->decide(gateHookUser(), 'invoices.approve', gateHookRequest()))->toBeNull();
});

it('denies a mapped ability when the session assurance is short', function (): void {
    gateHookRow('aal1');

    expect(gateHook()->decide(gateHookUser(), 'invoices.approve', gateHookRequest()))->toBeFalse();
});

it('denies a mapped ability when the session is revoked', function (): void {
    gateHookRow('aal2', ['revoked_at' => now()]);

    expect(gateHook()->decide(gateHookUser(), 'invoices.approve', gateHookRequest()))->toBeFalse();
});

it('DEFERS rather than granting when the assurance is sufficient', function (): void {
    /*
     * The single most important assertion in this file. Returning true here
     * would make Vouch an authorization grant path: any user whose session
     * happened to reach aal2 would be allowed an ability the host never gave
     * them. The hook is deny-only, so a satisfied requirement means "no
     * opinion", not "allow".
     */
    gateHookRow('aal3');

    expect(gateHook()->decide(gateHookUser(), 'invoices.approve', gateHookRequest()))->toBeNull();
});

it('never returns true for any level, mapped or not', function (string $acr, string $ability): void {
    gateHookRow($acr);

    expect(gateHook()->decide(gateHookUser(), $ability, gateHookRequest()))->not->toBeTrue();
})->with([
    ['aal0', 'invoices.approve'],
    ['aal1', 'invoices.approve'],
    ['aal2', 'invoices.approve'],
    ['aal3', 'invoices.approve'],
    ['aal0', 'invoices.view'],
    ['aal3', 'invoices.view'],
]);

it('denies a mapped ability when the request has a session but no vouch session row', function (): void {
    expect(gateHook()->decide(gateHookUser(), 'invoices.approve', gateHookRequest()))->toBeFalse();
});

it('defers when there is no session context to source assurance from', function (): void {
    /*
     * A queued job or console command has no HTTP session, so there is no
     * assurance to read -- not a weak one, none. Denying there would break
     * every background Gate check on a mapped ability, and this hook is not
     * the enforcement point that would justify the cost. The middleware
     * covers the requests that carry a session; 2.4 owns the token vocabulary
     * for the ones that do not.
     */
    expect(gateHook()->decide(gateHookUser(), 'invoices.approve', gateHookRequest(withSession: false)))->toBeNull();
});

it('never returns a response object, which the Gate would read as a grant', function (): void {
    // Any truthy return is an ALLOW to the Gate, so a RedirectResponse
    // returned from here would grant the very ability it meant to refuse.
    gateHookRow('aal1');

    expect(gateHook()->decide(gateHookUser(), 'invoices.approve', gateHookRequest()))->toBeBool();
});

it('denies when the session on file belongs to a different user', function (): void {
    /*
     * The row is found by session binding, which proves only that this browser
     * session has a vouch record -- not that the record describes the user the
     * Gate is being asked about. Reading it anyway would let one user's
     * assurance answer for another's ability check.
     */
    gateHookRow('aal3', ['user_id' => 999]);

    expect(gateHook()->decide(gateHookUser(), 'invoices.approve', gateHookRequest()))->toBeFalse();
});

it('defers for a user it cannot identify at all', function (): void {
    // A guest reaching a Gate check is refused by the authorization layer
    // regardless, and denying here would say nothing new.
    gateHookRow('aal1');

    expect(gateHook()->decide(null, 'invoices.approve', gateHookRequest()))->toBeNull();
});
