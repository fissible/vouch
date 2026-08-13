<?php

declare(strict_types=1);

use Fissible\Vouch\Http\AuthController;
use Fissible\Vouch\Http\Middleware\RequireAssurance;
use Fissible\Vouch\Http\AssuranceComparator;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Tests\Support\RecordingGuard;
use Fissible\Vouch\Vouch;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class);

/*
 * ONE session for the whole exchange, deliberately.
 *
 * Unit tests for the producer (RequireAssurance) and the consumer
 * (AuthController) do not prove they use the same session or the same key, nor
 * that consumption clears the value. Those are exactly the ways this contract
 * fails silently: the target is dropped, or worse, replayed. This test is the
 * only place the whole path is exercised end to end.
 */
function returnTargetSession(): Store
{
    static $store = null;

    if ($store === null) {
        $store = new Store('returntarget', new ArraySessionHandler(120), substr(str_repeat('returntargetsession', 3), 0, 40));
        $store->start();
    }

    return $store;
}

function protectedRequest(string $uri): Request
{
    $request = Request::create($uri);
    $request->setLaravelSession(returnTargetSession());

    return $request;
}

/**
 * @param  array<string, mixed>  $payload
 * @return array{result: string, handle: string|null, screen: array<string, mixed>, returnTo?: string|null}
 */
function returnTargetCall(array $payload): array
{
    $request = Request::create('/vouch/auth', 'POST', [], [], [], [], (string) json_encode($payload));
    $request->headers->set('Content-Type', 'application/json');
    $request->setLaravelSession(returnTargetSession());

    /** @var array{result: string, handle: string|null, screen: array<string, mixed>, returnTo?: string|null} $decoded */
    $decoded = json_decode((string) app(AuthController::class)($request)->getContent(), true);

    return $decoded;
}

/**
 * Drives a complete login and returns the authenticated envelope.
 *
 * @return array{result: string, handle: string|null, screen: array<string, mixed>, returnTo?: string|null}
 */
function completeLogin(): array
{
    $begin = returnTargetCall([]);
    returnTargetCall(['handle' => $begin['handle'], 'input' => ['identifier' => 'ada@acme.example']]);

    return returnTargetCall(['handle' => $begin['handle'], 'input' => ['password' => 'a-real-password']]);
}

beforeEach(function (): void {
    app()->instance(StatefulGuard::class, new RecordingGuard());
    config([
        'vouch.step_up.presentation_url' => '/auth/step-up',
        'vouch.step_up.default_return' => '/dashboard',
    ]);

    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password']], 'posture' => 'friendly',
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'a-real-password']);
    AuthIdentifier::create(['user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now()]);
});

it('carries a refused target through authentication and exposes it exactly once', function (): void {
    // 1. A protected request is refused; the middleware stores the target.
    $middleware = new RequireAssurance(app(AssuranceComparator::class));
    $refused = $middleware->handle(
        protectedRequest('/admin/settings?tab=security'),
        static fn (Request $r): Response => new Response('reached'),
        'aal2',
    );

    expect($refused->getStatusCode())->toBe(302);

    // 2. The user authenticates. The envelope carries THAT target.
    $authenticated = completeLogin();

    expect($authenticated['result'])->toBe('authenticated')
        ->and(data_get($authenticated, 'returnTo'))->toBe('/admin/settings?tab=security');

    // 3. A second completion gets only the configured default: consumption
    //    cleared it, so a stored target cannot be replayed by a later step-up.
    $second = completeLogin();

    expect(data_get($second, 'returnTo'))->toBe('/dashboard');
});

it('carries a target stored by the imperative entry point too', function (): void {
    // Vouch::stepUp() and RequireAssurance must store identically; two ways of
    // starting a step-up would be two places for the rules to drift.
    Vouch::stepUp('aal2', protectedRequest('/reports/export?range=90d'));

    expect(data_get(completeLogin(), 'returnTo'))->toBe('/reports/export?range=90d');
});

it('discards a hostile target through the whole path, not just in the validator', function (): void {
    Vouch::stepUp('aal2', protectedRequest('/safe'), '//evil.example/path');

    expect(data_get(completeLogin(), 'returnTo'))->toBe('/dashboard');
});

it('fails closed from the imperative entry point when no presentation url is set', function (): void {
    config(['vouch.step_up.presentation_url' => null]);

    Vouch::stepUp('aal2', protectedRequest('/admin'));
})->throws(RuntimeException::class);
