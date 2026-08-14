<?php

declare(strict_types=1);

use Fissible\Vouch\Http\Middleware\RequireAssurance;
use Fissible\Vouch\Http\Middleware\ValidatesVouchSession;
use Illuminate\Http\Request;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class);

/*
 * Both middleware carry a fail-closed guard, and neither guard had a test.
 */

it('lets a request with no session through untouched', function (): void {
    /*
     * Vouch registers in the web group, but a host can put it anywhere -- and a
     * stateless route has no session at all. Without the early return,
     * $request->session() is called on a request that has none, which throws.
     *
     * The failure is a 500 on every stateless route in the application, caused
     * by installing an auth package those routes do not use.
     */
    $request = Request::create('/api/health');

    $response = (new ValidatesVouchSession())->handle(
        $request,
        static fn (Request $r): Response => new Response('reached'),
    );

    expect($response->getContent())->toBe('reached');
});

it('refuses to demand assurance with no step-up destination configured', function (mixed $configured): void {
    /*
     * FAIL CLOSED, and the empty string is the case that matters. A missing key
     * is obviously unconfigured; an empty string looks configured and is not,
     * which is what a set-but-blank environment variable produces.
     *
     * Accepting it would redirect a user who needs to step up to '' -- back to
     * the current page, in a loop, with the protected route still refusing. 2.3
     * ships no routeable step-up page, so refusing loudly at the point of
     * misconfiguration is the only honest option.
     */
    config(['vouch.step_up.presentation_url' => $configured]);

    $request = Request::create('/admin');
    $request->setLaravelSession(app('session.store'));

    expect(fn (): Response => app(RequireAssurance::class)->handle(
        $request,
        static fn (Request $r): Response => new Response('reached'),
        'aal2',
    ))->toThrow(RuntimeException::class, 'Vouch requires vouch.step_up.presentation_url to be configured');
})->with([
    'absent' => [null],
    'set but blank' => [''],
    'not a string' => [42],
]);
