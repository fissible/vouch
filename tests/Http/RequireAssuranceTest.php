<?php

declare(strict_types=1);

use Fissible\Vouch\Http\AssuranceComparator;
use Fissible\Vouch\Http\IntendedDestination;
use Fissible\Vouch\Http\Middleware\RequireAssurance;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
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

/** A request with a principal and NO session at all. */
function sessionlessAssuranceRequest(): Request
{
    $request = Request::create('/admin/settings');
    $request->setUserResolver(static fn (): Authenticatable => assurancePrincipal(7));

    return $request;
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
     * the host guard stopped authenticating that user -- the record outlives
     * the authentication it was written for.
     */
    assuranceRow('aal2');

    expect(assuranceMiddleware()->handle(anonymousAssuranceRequest(), reached(), 'aal2'))
        ->toBeInstanceOf(\Illuminate\Http\RedirectResponse::class);
});

it('refuses when the record belongs to a different principal', function (): void {
    // The record is strong enough; it is simply not this user's.
    assuranceRow('aal2');

    $request = assuranceRequest(principalId: 8);

    expect(assuranceMiddleware()->handle($request, reached(), 'aal2'))
        ->toBeInstanceOf(\Illuminate\Http\RedirectResponse::class);
});

it('evaluates assurance normally when principal and record agree', function (): void {
    /*
     * The paired positive. Without it, a middleware changed to refuse
     * everything satisfies both tests above and breaks every gated route.
     */
    assuranceRow('aal2');

    expect(assuranceMiddleware()->handle(assuranceRequest(), reached(), 'aal2')->getContent())
        ->toBe('reached');
});

it('refuses without throwing when the request carries no session', function (): void {
    /*
     * A route can attach vouch.assurance outside the session middleware. Today
     * that throws on ->session()->getId(), and a gate that errors instead of
     * refusing is not fail-closed -- it is broken in a direction nobody chose.
     */
    assuranceRow('aal2');

    $response = assuranceMiddleware()->handle(sessionlessAssuranceRequest(), reached(), 'aal2');

    expect($response)->toBeInstanceOf(\Illuminate\Http\RedirectResponse::class)
        ->and($response->getStatusCode())->toBeLessThan(500);
});

it('does not try to remember a destination when there is no session to remember it in', function (): void {
    /*
     * Guarding the READ is not enough: the refusal path writes the intended
     * destination through $request->session() and throws for exactly the same
     * reason. There is nowhere to remember it to and nothing that would later
     * read it.
     */
    assuranceRow('aal2');

    $request = sessionlessAssuranceRequest();

    assuranceMiddleware()->handle($request, reached(), 'aal2');

    expect($request->hasSession())->toBeFalse();
});
