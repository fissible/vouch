<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

use Fissible\Vouch\Http\Middleware\ValidatesVouchSession;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Symfony\Component\HttpFoundation\Response;

/*
 * The middleware is exercised directly rather than through a routed request.
 *
 * Laravel's test client does not share a session with the test body, and with
 * the array driver the ID does not survive between requests either — verified,
 * not assumed. So a route-level test cannot arrange "this exact session is
 * revoked" without plumbing that would itself be the thing under test. handle()
 * is the whole contract; end-to-end coverage through real routes arrives in the
 * HTTP surface task, where the flow issues the session it later reads.
 */
/**
 * Laravel's Store::setId() silently discards any ID that is not 40
 * alphanumeric characters and generates a random one instead — so a readable
 * label like 'revoked-session' never reaches the query, and the middleware
 * looks like it passed the request through when it simply never saw the row.
 */
function vouchSessionId(string $label): string
{
    // ctype_alnum: hyphens fail too, not just the length check.
    return substr(str_pad((string) preg_replace('/[^a-zA-Z0-9]/', '', $label), 40, 'x'), 0, 40);
}

function requestWithSession(string $sessionId): Request
{
    $store = new Store('vouch_test_session', new ArraySessionHandler(120), $sessionId);
    $store->start();

    $request = Request::create('/vouch-probe');
    $request->setLaravelSession($store);

    return $request;
}

function passThrough(): Closure
{
    return static fn (Request $request): Response => new Response('reached');
}

it('lets a request with no vouch record through untouched', function (): void {
    /*
     * Vouch does not own every session. A request it has no record of is not
     * vouch's business, and refusing it would break the host's own auth for
     * every application that installs the package.
     */
    $response = (new ValidatesVouchSession())->handle(requestWithSession(vouchSessionId('unknown-session')), passThrough());

    expect($response->getContent())->toBe('reached');
});

it('lets a live session through', function (): void {
    AuthSession::create([
        'session_binding' => SessionBinding::for(vouchSessionId('live-session'), BindingDomain::Session),
        'user_id' => 7,
        'amr' => ['password'],
    ]);

    $response = (new ValidatesVouchSession())->handle(requestWithSession(vouchSessionId('live-session')), passThrough());

    expect($response->getContent())->toBe('reached');
});

it('refuses a revoked session and destroys it', function (): void {
    /*
     * The control that makes revokeSiblings() real. Setting revoked_at is inert
     * on its own: the host's cookie still works, so without this read
     * "all other sessions invalidated on password change" is a documented
     * promise with no mechanism behind it.
     */
    AuthSession::create([
        'session_binding' => SessionBinding::for(vouchSessionId('revoked-session'), BindingDomain::Session),
        'user_id' => 7,
        'amr' => ['password'],
        'revoked_at' => now(),
        'revoked_reason' => RevokedReason::PasswordChanged,
    ]);

    $request = requestWithSession(vouchSessionId('revoked-session'));
    $request->session()->put('vouch.probe.marker', 'present');

    $response = (new ValidatesVouchSession())->handle($request, passThrough());

    // The marker, not the ID: proves the session was destroyed rather than
    // merely rotated by something else in the stack.
    expect($response->getContent())->not->toBe('reached')
        ->and($response->getStatusCode())->toBe(302)
        ->and($request->session()->has('vouch.probe.marker'))->toBeFalse();
});

it('is registered in the web group rather than only aliased', function (): void {
    /*
     * A runtime check is authoritative only on requests that traverse it, and
     * vouch does not control the host's route stack. If this middleware were
     * merely aliased, every host route would be unguarded while the alias
     * looked like protection.
     */
    $group = app(\Illuminate\Routing\Router::class)->getMiddlewareGroups()['web'] ?? [];

    expect($group)->toContain(\Fissible\Vouch\Http\Middleware\ValidatesVouchSession::class);
});
