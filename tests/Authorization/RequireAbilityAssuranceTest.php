<?php

declare(strict_types=1);

use Fissible\Vouch\Http\Middleware\RequireAbilityAssurance;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class);

/*
 * The PRIMARY enforcement point (2.3d Task 5b).
 *
 * Task 5a's probes established that a deny-only Gate::before hook is bypassed
 * whenever an earlier hook grants, and that a hook Vouch registers always
 * lands last. spatie's hook grants precisely when the user HOLDS the
 * permission -- the only case an assurance requirement exists to constrain. So
 * enforcement has to happen before the authorization call runs, which means
 * route middleware. The Gate hook is defense in depth and is covered
 * separately.
 */

function abilityAssuranceSessionId(): string
{
    return substr(str_repeat('abilityassurance', 3), 0, 40);
}

/**
 * @param  list<string>  $middleware
 */
function abilityAssuranceRequest(
    array $middleware = ['permission:invoices.approve'],
    string $uri = '/invoices/9/approve?from=list',
    bool $authenticated = true,
    bool $withSession = true,
    bool $expectsJson = false,
): Request {
    $request = Request::create($uri, 'POST', server: $expectsJson ? ['HTTP_ACCEPT' => 'application/json'] : []);

    if ($withSession) {
        $store = new Store('vouch_ability', new ArraySessionHandler(120), abilityAssuranceSessionId());
        $store->start();
        $request->setLaravelSession($store);
    }

    $route = new Route(['POST'], '/invoices/{id}/approve', ['uses' => fn (): string => 'ok']);
    $route->middleware($middleware);
    $request->setRouteResolver(fn (): Route => $route);

    if ($authenticated) {
        $user = new Fissible\Vouch\Tests\Support\Authorization\Models\PlainProbeUser;
        $user->id = 7;
        $request->setUserResolver(fn (): object => $user);
    }

    return $request;
}

/**
 * @param  array<string, mixed>  $extra
 */
function abilityAssuranceRow(string $acr, array $extra = []): AuthSession
{
    return AuthSession::create(array_merge([
        'session_binding' => SessionBinding::for(abilityAssuranceSessionId(), BindingDomain::Session),
        'user_id' => 7,
        'amr' => ['password'],
        'acr' => $acr,
        'assurance_proof' => sessionProof(7, $acr),
        'weakest_satisfied_at' => now(),
    ], $extra));
}

function abilityAssuranceNext(): Closure
{
    return static fn (Request $request): Response => new Response('reached');
}

function abilityAssuranceMiddleware(): RequireAbilityAssurance
{
    return app(RequireAbilityAssurance::class);
}

beforeEach(function (): void {
    config([
        'vouch.step_up.presentation_url' => '/auth/step-up',
        'vouch.assurance_requirements' => [
            'invoices.approve' => 'aal2',
            // Deliberately underivable: the shipped vocabulary caps at aal2, so
            // this route can never be satisfied. It is a REQUIREMENT, not a
            // fixture level, and requirements may name any known level -- which
            // is why the strongestFor() tests below still work.
            'users.impersonate' => 'aal3',
        ],
    ]);
});

it('lets a request through when the route names no mapped ability', function (): void {
    abilityAssuranceRow('aal1');

    $response = abilityAssuranceMiddleware()->handle(
        abilityAssuranceRequest(['permission:invoices.view']),
        abilityAssuranceNext(),
    );

    expect($response->getContent())->toBe('reached');
});

it('lets a request through when the map is empty', function (): void {
    config(['vouch.assurance_requirements' => []]);
    abilityAssuranceRow('aal1');

    expect(abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext())->getContent())
        ->toBe('reached');
});

it('lets a sufficient session through', function (): void {
    abilityAssuranceRow('aal2');

    expect(abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext())->getContent())
        ->toBe('reached');
});

it('lets a STRONGER session satisfy a weaker requirement', function (): void {
    /*
     * Ordered comparison, never equality. Refusing a stronger session is a
     * lockout that looks like a security win.
     *
     * This read aal3-over-aal2 until 2.4 Task 2a. No proof derives aal3, so the
     * pair moved down a rung: aal2 over an aal1 route makes the same point with
     * a session someone can actually hold.
     */
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal1']]);
    abilityAssuranceRow('aal2');

    expect(abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext())->getContent())
        ->toBe('reached');
});

it('sends an insufficient interactive request to step up', function (): void {
    abilityAssuranceRow('aal1');

    $response = abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext());

    expect($response)->toBeInstanceOf(RedirectResponse::class)
        ->and($response->headers->get('Location'))->toBe('/auth/step-up');
});

it('remembers the refused destination server side, not from the client', function (): void {
    abilityAssuranceRow('aal1');

    $request = abilityAssuranceRequest();
    abilityAssuranceMiddleware()->handle($request, abilityAssuranceNext());

    expect($request->session()->get('vouch.step_up.intended'))->toBe('/invoices/9/approve?from=list');
});

it('requires the STRONGEST mapped level when the route lists alternatives', function (): void {
    // Fail closed: the authorization layer grants on ANY of them and Vouch
    // cannot see which one granted.
    abilityAssuranceRow('aal2');

    $response = abilityAssuranceMiddleware()->handle(
        abilityAssuranceRequest(['permission:invoices.approve|users.impersonate']),
        abilityAssuranceNext(),
    );

    expect($response)->toBeInstanceOf(RedirectResponse::class);
});

it('refuses an unmapped-ability route no differently than before', function (): void {
    // Deny only. The map may never turn a request the host would have refused
    // into one it allows, so a route with no mapped ability is untouched --
    // including when the session is missing entirely.
    $response = abilityAssuranceMiddleware()->handle(
        abilityAssuranceRequest(['permission:invoices.view']),
        abilityAssuranceNext(),
    );

    expect($response->getContent())->toBe('reached');
});

it('refuses a request whose session is revoked', function (): void {
    abilityAssuranceRow('aal2', ['revoked_at' => now()]);

    expect(abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext()))
        ->toBeInstanceOf(RedirectResponse::class);
});

it('refuses a request with no vouch session row at all', function (): void {
    expect(abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext()))
        ->toBeInstanceOf(RedirectResponse::class);
});

it('lets a guest through so the host auth middleware can deny it', function (): void {
    /*
     * This middleware sits in the `web` group, so it runs BEFORE route
     * middleware -- including `auth`. A guest has no assurance and never will
     * until they log in, so refusing here would replace the login redirect
     * with a step-up redirect and strand them.
     *
     * It is not a bypass: a guest cannot pass the authorization check either.
     * Every path that reaches an ability check denies an unauthenticated user.
     */
    $response = abilityAssuranceMiddleware()->handle(
        abilityAssuranceRequest(authenticated: false),
        abilityAssuranceNext(),
    );

    expect($response->getContent())->toBe('reached');
});

it('lets a request with no matched route through', function (): void {
    $request = Request::create('/invoices/9/approve', 'POST');
    $store = new Store('vouch_ability', new ArraySessionHandler(120), abilityAssuranceSessionId());
    $store->start();
    $request->setLaravelSession($store);

    expect(abilityAssuranceMiddleware()->handle($request, abilityAssuranceNext())->getContent())->toBe('reached');
});

/*
 * Non-interactive callers. The map is session-sourced until 2.4, and 2.4 owns
 * the RFC 9470 rendering -- so the refusal here must STATE the shortfall
 * rather than fail open, without inventing a second vocabulary that 2.4 would
 * then have to keep compatible.
 */

it('refuses an insufficient JSON request with 403 rather than a redirect', function (): void {
    abilityAssuranceRow('aal1');

    $response = abilityAssuranceMiddleware()->handle(
        abilityAssuranceRequest(expectsJson: true),
        abilityAssuranceNext(),
    );

    expect($response->getStatusCode())->toBe(403)
        ->and($response)->not->toBeInstanceOf(RedirectResponse::class);
});

it('states the shortfall in the JSON refusal instead of failing open', function (): void {
    abilityAssuranceRow('aal1');

    $response = abilityAssuranceMiddleware()->handle(
        abilityAssuranceRequest(expectsJson: true),
        abilityAssuranceNext(),
    );

    $payload = json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR);

    expect($payload)->toMatchArray([
        'error' => 'insufficient_assurance',
        'required' => 'aal2',
        'held' => 'aal1',
    ]);
});

it('reports the held level as null when there is no session to source one from', function (): void {
    $response = abilityAssuranceMiddleware()->handle(
        abilityAssuranceRequest(expectsJson: true),
        abilityAssuranceNext(),
    );

    /** @var array<string, mixed> $payload */
    $payload = json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR);

    expect($payload['held'])->toBeNull()
        ->and($payload['required'])->toBe('aal2');
});

it('refuses a token request that carries no session at all', function (): void {
    // `auth:sanctum` authenticates without a session. There is no assurance to
    // read, and 2.4 owns the token vocabulary, so state the refusal now.
    $response = abilityAssuranceMiddleware()->handle(
        abilityAssuranceRequest(withSession: false, expectsJson: true),
        abilityAssuranceNext(),
    );

    expect($response->getStatusCode())->toBe(403);
});

it('does not try to redirect a sessionless request', function (): void {
    // Redirecting needs somewhere to record the intended destination, and
    // there is no session to record it in. Refusing is the only honest answer.
    $response = abilityAssuranceMiddleware()->handle(
        abilityAssuranceRequest(withSession: false),
        abilityAssuranceNext(),
    );

    expect($response->getStatusCode())->toBe(403);
});

it('fails closed when a route demands assurance and no step up page is configured', function (): void {
    // Same contract as RequireAssurance: guessing a destination sends browsers
    // to a POST-only endpoint, which is worse than refusing.
    config(['vouch.step_up.presentation_url' => null]);
    abilityAssuranceRow('aal1');

    expect(fn () => abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext()))
        ->toThrow(RuntimeException::class, 'presentation_url');
});

it('does not consult the step up configuration on a request it lets through', function (): void {
    // The fail-closed check must not turn an unaffected route into a 500 just
    // because the host has not configured step-up yet.
    config(['vouch.step_up.presentation_url' => null]);
    abilityAssuranceRow('aal2');

    expect(abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext())->getContent())
        ->toBe('reached');
});

/*
 * The session row is looked up by session binding. That alone does not prove
 * it belongs to the person making the request.
 */

it('refuses when the vouch session belongs to a different user', function (): void {
    /*
     * A binding-only lookup trusts the session cookie to identify the user. If
     * the host re-authenticates within the same Laravel session — an
     * impersonation exit, a guard swap, a login that does not rotate the id —
     * the row on file describes SOMEONE ELSE's assurance, and reading it would
     * hand this request an assurance level nobody proved for it.
     */
    abilityAssuranceRow('aal2', ['user_id' => 999]);

    expect(abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext()))
        ->toBeInstanceOf(RedirectResponse::class);
});

it('accepts a session row that belongs to the authenticated user', function (): void {
    abilityAssuranceRow('aal2', ['user_id' => 7]);

    expect(abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext())->getContent())
        ->toBe('reached');
});

it('refuses rather than passing through when the configured map is invalid', function (): void {
    /*
     * An unreadable map must never degrade to "no requirement". That is the
     * silent-disable failure this whole task exists to prevent, and it would
     * be indistinguishable from a correctly empty map.
     */
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal9']]);

    expect(fn () => abilityAssuranceMiddleware()->handle(abilityAssuranceRequest(), abilityAssuranceNext()))
        ->toThrow(InvalidArgumentException::class);
});
