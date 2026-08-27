<?php

declare(strict_types=1);

use Fissible\Vouch\Http\Middleware\RequireAbilityAssurance;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;

uses(RefreshDatabase::class);

/*
 * Wiring and shipped defaults (2.3d Task 5b).
 *
 * The middleware only closes the stated gap if it is on by default. A host who
 * forgot `vouch.assurance:aal2` will equally forget to add a new middleware,
 * so an opt-in enforcement point enforces nothing. This follows the
 * ValidatesVouchSession precedent, which is pushed into a group for the same
 * reason.
 *
 * End-to-end proof that the ordering actually holds lives in
 * AbilityAssuranceRouteTest; what is asserted here is the installation
 * contract a host reads when deciding where their own routes are covered.
 */

it('enforces in the web group', function (): void {
    expect(app(Router::class)->getMiddlewareGroups()['web'] ?? [])
        ->toContain(RequireAbilityAssurance::class);
});

it('enforces in the api group as well', function (): void {
    /*
     * Web-only coverage would leave every API route depending on the Gate
     * hook, which Task 5a measured as bypassable. A token request cannot prove
     * assurance until 2.4, so a mapped ability there is refused rather than
     * allowed — fail closed, and only ever on abilities the host explicitly
     * put in the map.
     */
    expect(app(Router::class)->getMiddlewareGroups()['api'] ?? [])
        ->toContain(RequireAbilityAssurance::class);
});

it('offers an alias so a custom middleware group can be covered too', function (): void {
    // A host with neither `web` nor `api` on a protected group has to be able
    // to add the same enforcement by name rather than by class path.
    expect(app(Router::class)->getMiddleware())->toHaveKey('vouch.ability');
});

it('leaves the existing vouch.assurance alias alone', function (): void {
    // Task 6's composition recipe still names it and 2.4's RFC 9470 rendering
    // extends it. The ability map is additional, not a replacement.
    expect(app(Router::class)->getMiddleware())->toHaveKey('vouch.assurance');
});

it('registers a gate hook that actually denies, not merely a callback', function (): void {
    /*
     * Asserting that SOME callback is registered proves nothing: a no-op
     * closure, or one wired to the wrong object, would satisfy it. Drive the
     * Gate instead and check the decision.
     */
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);
    Gate::define('invoices.approve', fn (): bool => true);

    $id = session()->getId();
    AuthSession::create([
        'session_binding' => SessionBinding::for($id, BindingDomain::Session),
        'user_id' => 7,
        'amr' => ['password'],
        'acr' => 'aal1',
    ]);

    $user = new Fissible\Vouch\Tests\Support\Authorization\Models\PlainProbeUser;
    $user->id = 7;

    expect(Gate::forUser($user)->allows('invoices.approve'))->toBeFalse();
});

it('does not let the gate hook decide an ability the map does not name', function (): void {
    config(['vouch.assurance_requirements' => ['invoices.approve' => 'aal2']]);
    Gate::define('invoices.view', fn (): bool => true);

    $user = new Fissible\Vouch\Tests\Support\Authorization\Models\PlainProbeUser;
    $user->id = 7;

    expect(Gate::forUser($user)->allows('invoices.view'))->toBeTrue();
});

/*
 * Shipped defaults. A host that never publishes the config file must get a
 * package that boots, enforces nothing it was not told to enforce, and does
 * not fail on a missing key.
 */

it('ships an empty requirement map by default', function (): void {
    expect(config('vouch.assurance_requirements'))->toBe([]);
});

it('ships an empty declared ability list by default', function (): void {
    expect(config('vouch.declared_abilities'))->toBe([]);
});

it('ships strict mode off by default', function (): void {
    // Installing an authentication package must never refuse to boot an app
    // that was working a minute earlier.
    expect(config('vouch.assurance_strict'))->toBeFalse();
});
