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
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class);

function assuranceSessionId(): string
{
    return substr(str_repeat('assurancesession', 3), 0, 40);
}

function assuranceRequest(string $uri = '/admin/settings?tab=security'): Request
{
    $store = new Store('assurance', new ArraySessionHandler(120), assuranceSessionId());
    $store->start();

    $request = Request::create($uri);
    $request->setLaravelSession($store);

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
    assuranceRow('aal3', ['revoked_at' => now(), 'revoked_reason' => RevokedReason::PasswordChanged]);

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
