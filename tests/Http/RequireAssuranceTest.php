<?php

declare(strict_types=1);

use Fissible\Vouch\Http\AssuranceComparator;
use Fissible\Vouch\Http\IntendedDestination;
use Fissible\Vouch\Http\Middleware\RequireAssurance;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Tests\Support\Http\SessionlessProbeRequest;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class);

function assuranceSessionId(): string
{
    return substr(str_repeat('assurancesession', 3), 0, 40);
}

/**
 * A request carrying BOTH a session and an authenticated principal.
 *
 * Every test here used to run with no principal at all, which quietly made
 * them all exercise the case §3j now refuses: a record evaluated on its own,
 * with nothing establishing who was asking. Authenticating by default keeps
 * each test about the thing it was written for, and the unauthenticated case
 * gets its own explicit coverage below.
 */
function assuranceRequest(string $uri = '/admin/settings?tab=security', ?int $principalId = 7): Request
{
    $store = new Store('assurance', new ArraySessionHandler(120), assuranceSessionId());
    $store->start();

    $request = Request::create($uri);
    $request->setLaravelSession($store);

    if ($principalId !== null) {
        $request->setUserResolver(static fn (): Authenticatable => assurancePrincipal($principalId));
    }

    return $request;
}

/** A minimal principal: the middleware needs an identifier and nothing else. */
function assurancePrincipal(int $id): Authenticatable
{
    return new class($id) implements Authenticatable
    {
        public function __construct(private readonly int $id) {}

        public function getAuthIdentifierName(): string
        {
            return 'id';
        }

        public function getAuthIdentifier(): int
        {
            return $this->id;
        }

        public function getAuthPasswordName(): string
        {
            return 'password';
        }

        public function getAuthPassword(): string
        {
            return '';
        }

        public function getRememberToken(): string
        {
            return '';
        }

        public function setRememberToken($value): void {}

        public function getRememberTokenName(): string
        {
            return 'remember_token';
        }
    };
}

/** A request with a session and NO principal. */
function anonymousAssuranceRequest(string $uri = '/admin/settings?tab=security'): Request
{
    return assuranceRequest($uri, null);
}

/**
 * A request with NO session, which records every attempt to reach for one.
 *
 * @param  int|null  $principalId  null for the guest case.
 */
function sessionlessAssuranceRequest(?int $principalId = 7): SessionlessProbeRequest
{
    $request = SessionlessProbeRequest::for();

    if ($principalId !== null) {
        $request->setUserResolver(static fn (): Authenticatable => assurancePrincipal($principalId));
    }

    return $request;
}

/**
 * Count resolutions of the CONTAINER session store.
 *
 * A sessionless refusal could remember its destination through
 * `app('session.store')` rather than `$request->session()`, and no request-level
 * probe would see it. This counts the resolution itself, so the fallback is
 * visible whether or not anything is written.
 */
function countingContainerSession(int &$resolutions): void
{
    app()->bind('session.store', static function () use (&$resolutions): Store {
        $resolutions++;

        return new Store('container-probe', new ArraySessionHandler(120), 'container-probe');
    });

    /*
     * The MANAGER too. `session()->driver()` returns the same store without
     * ever resolving `session.store`, so watching that binding alone leaves a
     * working fallback invisible -- verified, not assumed: a refusal built on
     * `IntendedDestination(session()->driver())` remembers the path with the
     * store counter still reading zero.
     */
    $manager = app('session');

    app()->bind('session', static function () use (&$resolutions, $manager): mixed {
        $resolutions++;

        return $manager;
    });
}

/** A $next that records whether the protected handler was reached. */
function countingNext(int &$calls): Closure
{
    return static function (Request $request) use (&$calls): Response {
        $calls++;

        return new Response('reached');
    };
}

/** The refusal this middleware is configured to produce. */
function expectRefusal(Response $response): void
{
    expect($response->getStatusCode())->toBe(302)
        ->and($response->headers->get('Location'))->toBe('/auth/step-up');
}

/**
 * @param  array<string, mixed>  $extra
 */
function assuranceRow(string $acr, array $extra = []): AuthSession
{
    return AuthSession::create(array_merge([
        'session_binding' => SessionBinding::for(assuranceSessionId(), BindingDomain::Session),
        'user_id' => 7,
        'amr' => ['password'],
        'acr' => $acr,
        // 2.4 Task 2a: a level without a proof is refused. Fixtures that mean
        // "a session at this level" must now carry evidence of it.
        'assurance_proof' => sessionProof(7, $acr),
        'weakest_satisfied_at' => now(),
    ], $extra));
}

function assuranceMiddleware(): RequireAssurance
{
    return new RequireAssurance(app(AssuranceComparator::class));
}

function reached(): Closure
{
    return static fn (Request $request): Response => new Response('reached');
}

beforeEach(function (): void {
    config(['vouch.step_up.presentation_url' => '/auth/step-up']);
});

it('lets a sufficient session through', function (): void {
    assuranceRow('aal2');

    expect(assuranceMiddleware()->handle(assuranceRequest(), reached(), 'aal2')->getContent())->toBe('reached');
});

it('lets a STRONGER session satisfy a weaker requirement', function (): void {
    /*
     * Ordered comparison, not string equality. Refusing a stronger session is a
     * lockout that looks like a security win -- an aal2 user bounced off an
     * aal1 route forever.
     */
    assuranceRow('aal2');

    expect(assuranceMiddleware()->handle(assuranceRequest(), reached(), 'aal1')->getContent())->toBe('reached');
});

it('redirects an insufficient session to the configured presentation url', function (): void {
    assuranceRow('aal1');

    $response = assuranceMiddleware()->handle(assuranceRequest(), reached(), 'aal2');

    expect($response->getStatusCode())->toBe(302)
        // redirect()->to() returns an absolute URL; the path is what is asserted.
        ->and($response->headers->get('Location'))->toEndWith('/auth/step-up');
});

it('remembers the refused path, from the request rather than a parameter', function (): void {
    assuranceRow('aal1');

    $request = assuranceRequest('/admin/settings?tab=security');
    assuranceMiddleware()->handle($request, reached(), 'aal2');

    expect((new IntendedDestination($request->session()))->consume())->toBe('/admin/settings?tab=security');
});

it('fails closed when no presentation url is configured', function (): void {
    /*
     * 2.3 ships no routeable step-up page, so a browser redirected to the JSON
     * endpoint issues a GET and receives 405. Guessing a destination would be
     * worse than refusing.
     */
    config(['vouch.step_up.presentation_url' => null]);
    assuranceRow('aal1');

    /*
     * The config key is asserted, not just the exception class. RuntimeException
     * is broad enough that an unrelated failure inside handle() would satisfy a
     * class-only assertion and this test would still pass while saying nothing —
     * the same gap StepUpFailClosedTest already closes for Vouch::stepUp(), and
     * the identity artifact is the same: the setting the operator has to set.
     */
    expect(fn (): mixed => assuranceMiddleware()->handle(assuranceRequest(), reached(), 'aal2'))
        ->toThrow(RuntimeException::class, 'vouch.step_up.presentation_url');
});

it('refuses a revoked session however strong its recorded assurance', function (): void {
    assuranceRow('aal2', ['revoked_at' => now(), 'revoked_reason' => RevokedReason::PasswordChanged]);

    expect(assuranceMiddleware()->handle(assuranceRequest(), reached(), 'aal1')->getStatusCode())->toBe(302);
});

it('refuses a grace session, and is not what contains one', function (): void {
    /*
     * A grace session is never authenticated, so the host's own auth middleware
     * denies a protected route before assurance is considered. This assertion
     * documents fail-closed behaviour here; it is NOT grace's containment.
     */
    assuranceRow('aal2', ['recovery_grace_expires_at' => now()->addMinutes(15)]);

    expect(assuranceMiddleware()->handle(assuranceRequest(), reached(), 'aal1')->getStatusCode())->toBe(302);
});

it('refuses when there is no vouch session at all', function (): void {
    expect(assuranceMiddleware()->handle(assuranceRequest(), reached(), 'aal1')->getStatusCode())->toBe(302);
});

it('refuses when no principal is authenticated', function (): void {
    /*
     * A record is not evidence of who is asking. Without a principal a stale or
     * partially logged-out host session still satisfies the requirement after
     * the host guard stopped authenticating that user.
     *
     * The refused RESPONSE is asserted, not its class: this middleware returns
     * Symfony's RedirectResponse, so an Illuminate\Http\RedirectResponse check
     * would stay red against a correct fix. A class check would also accept a
     * redirect to the wrong place.
     */
    assuranceRow('aal2');
    $calls = 0;

    expectRefusal(assuranceMiddleware()->handle(anonymousAssuranceRequest(), countingNext($calls), 'aal2'));

    // The boundary held. A middleware that called $next, discarded its response
    // and then redirected would satisfy the assertion above.
    expect($calls)->toBe(0);
});

it('refuses when the record belongs to a different principal', function (): void {
    // The record is strong enough; it is simply not this user's.
    assuranceRow('aal2');
    $calls = 0;

    expectRefusal(assuranceMiddleware()->handle(assuranceRequest(principalId: 8), countingNext($calls), 'aal2'));

    expect($calls)->toBe(0);
});

it('evaluates assurance normally when principal and record agree', function (): void {
    /*
     * Kept despite overlapping the sufficient-session test above, because it is
     * the case this change is ABOUT: the two other tests say when the principal
     * check refuses, and this one says the check does not refuse everything.
     */
    assuranceRow('aal2');
    $calls = 0;

    expect(assuranceMiddleware()->handle(assuranceRequest(), countingNext($calls), 'aal2')->getContent())
        ->toBe('reached')
        ->and($calls)->toBe(1);
});

it('refuses a request with no session without reaching for one', function (): void {
    /*
     * A route can attach vouch.assurance outside the session middleware. Today
     * that throws on ->session()->getId(), and a gate that errors instead of
     * refusing is not fail-closed.
     *
     * Guarding the READ alone is not enough: the refusal path writes an
     * intended destination through $request->session() and throws for the same
     * reason. The marker exception makes that observable -- if it escapes, the
     * middleware reached for a session it was told did not exist.
     */
    assuranceRow('aal2');
    $calls = 0;
    $containerResolutions = 0;
    countingContainerSession($containerResolutions);

    $request = sessionlessAssuranceRequest();

    expectRefusal(assuranceMiddleware()->handle($request, countingNext($calls), 'aal2'));

    /*
     * The COUNT, not the exception. The marker extends RuntimeException, so an
     * implementation that tried the session, caught the throwable and returned
     * the right redirect would be indistinguishable from one that never
     * touched it. The counter is recorded before the throw and survives being
     * caught.
     */
    expect($request->sessionTouches)->toBe(0)
        ->and($containerResolutions)->toBe(0)
        ->and($calls)->toBe(0);
});

it('refuses a guest with no session, which is both branches at once', function (): void {
    /*
     * The combined case. An implementation that refused guests EARLY, before
     * the session guard, could still touch session state on that branch -- the
     * authenticated sessionless test would never reach it.
     */
    assuranceRow('aal2');
    $calls = 0;
    $containerResolutions = 0;
    countingContainerSession($containerResolutions);

    $request = sessionlessAssuranceRequest(null);

    expectRefusal(assuranceMiddleware()->handle($request, countingNext($calls), 'aal2'));

    expect($request->sessionTouches)->toBe(0)
        ->and($containerResolutions)->toBe(0)
        ->and($calls)->toBe(0);
});

it('does not accept a record from a different session of the same principal', function (): void {
    /*
     * A fix that looked the record up by PRINCIPAL rather than by binding would
     * satisfy every other test here: the principal matches, the evidence is
     * strong, and the refusal cases all vary the principal. This varies the
     * BINDING instead -- the same user, a different session -- which is the
     * decoy that tells the two lookups apart.
     */
    assuranceRow('aal2', ['session_binding' => SessionBinding::for('a-different-session-of-the-same-user', BindingDomain::Session)]);
    $calls = 0;

    expectRefusal(assuranceMiddleware()->handle(assuranceRequest(), countingNext($calls), 'aal2'));

    expect($calls)->toBe(0);
});
