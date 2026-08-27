<?php

declare(strict_types=1);

use Fissible\Vouch\Authorization\RouteAbilityScanner;
use Illuminate\Routing\Route;

/*
 * Reads the ability names a route already declares in its own middleware.
 *
 * This is what makes the map worth having. The gap it closes is a developer
 * writing `permission:invoices.approve` and forgetting the assurance
 * middleware -- so requiring them to write a SECOND ability name would close
 * nothing. Vouch reads the one they already wrote.
 *
 * Ability names are gathered, never judged. A name that matches nothing in the
 * map is simply not a requirement; that decision belongs to the map.
 */

/**
 * @param  list<string>  $middleware
 */
function scannedAbilities(array $middleware): array
{
    $route = new Route(['GET'], '/probe', ['uses' => fn (): string => 'ok']);
    $route->middleware($middleware);

    return app(RouteAbilityScanner::class)->abilitiesFor($route);
}

it('finds nothing on a route with no middleware', function (): void {
    expect(scannedAbilities([]))->toBe([]);
});

it('finds nothing on middleware it does not recognise', function (): void {
    expect(scannedAbilities(['web', 'auth', 'throttle:60,1']))->toBe([]);
});

it("reads Laravel's own can: middleware", function (): void {
    expect(scannedAbilities(['can:invoices.approve']))->toBe(['invoices.approve']);
});

it('reads can: written as the fully qualified middleware class', function (): void {
    // A host that skips the alias, and what Route::can() compiles to.
    expect(scannedAbilities([Illuminate\Auth\Middleware\Authorize::class . ':invoices.approve']))
        ->toBe(['invoices.approve']);
});

it('ignores the model argument of can:, which is not an ability', function (): void {
    expect(scannedAbilities(['can:update,invoice']))->toBe(['update']);
});

it("reads spatie's permission: middleware", function (): void {
    expect(scannedAbilities(['permission:invoices.approve']))->toBe(['invoices.approve']);
});

it('reads spatie permission: written as the fully qualified middleware class', function (): void {
    expect(scannedAbilities([Spatie\Permission\Middleware\PermissionMiddleware::class . ':invoices.approve']))
        ->toBe(['invoices.approve']);
});

it('reads every alternative in a pipe separated permission list', function (): void {
    expect(scannedAbilities(['permission:invoices.approve|invoices.view']))
        ->toBe(['invoices.approve', 'invoices.view']);
});

it("ignores spatie's guard argument, which is not an ability", function (): void {
    // `permission:<permission>,<guard>` -- the second comma argument names a
    // guard. Treating it as an ability would put a phantom key in the scan.
    expect(scannedAbilities(['permission:invoices.approve,web']))->toBe(['invoices.approve']);
});

it('reads the permission alternatives of role_or_permission:', function (): void {
    /*
     * The survey found this middleware only half enforceable: its permission
     * branch reaches the Gate and its role branch does not. Vouch cannot tell
     * a role name from a permission name here, so it gathers both and lets the
     * map decide -- a role name that is not in the map is simply not a
     * requirement.
     */
    expect(scannedAbilities(['role_or_permission:admin|invoices.approve']))
        ->toBe(['admin', 'invoices.approve']);
});

it("never reads spatie's role: middleware as an ability", function (): void {
    // `role:` never reaches the Gate at all, and a role name is not an
    // ability name. Scanning it would apply a requirement to the wrong key.
    expect(scannedAbilities(['role:admin']))->toBe([]);
});

it('ignores a recognised middleware with no parameter at all', function (): void {
    expect(scannedAbilities(['can', 'permission']))->toBe([]);
});

it('ignores an empty parameter rather than yielding an empty ability name', function (): void {
    expect(scannedAbilities(['can:', 'permission:|']))->toBe([]);
});

it('gathers abilities from several middleware on one route', function (): void {
    expect(scannedAbilities(['can:invoices.approve', 'permission:users.impersonate']))
        ->toBe(['invoices.approve', 'users.impersonate']);
});

it('reports each ability once, in the order first seen', function (): void {
    expect(scannedAbilities(['can:invoices.approve', 'permission:invoices.approve|users.impersonate']))
        ->toBe(['invoices.approve', 'users.impersonate']);
});

it('trims surrounding whitespace from an ability name', function (): void {
    expect(scannedAbilities(['permission:invoices.approve | invoices.view']))
        ->toBe(['invoices.approve', 'invoices.view']);
});

it('sees middleware inherited from the route group', function (): void {
    // Group middleware lands in the route's own list, and a host that guards a
    // whole admin group with one `can:` is the case most likely to forget a
    // per-route assurance middleware.
    Illuminate\Support\Facades\Route::middleware('can:admin.access')->group(function (): void {
        Illuminate\Support\Facades\Route::get('/probe-group', fn (): string => 'ok');
    });

    $route = collect(app('router')->getRoutes()->getRoutes())
        ->firstOrFail(fn (Route $candidate): bool => $candidate->uri() === 'probe-group');

    expect(app(RouteAbilityScanner::class)->abilitiesFor($route))->toBe(['admin.access']);
});

it("ignores the guard argument on role_or_permission: too", function (): void {
    // `role_or_permission:<names>,<guard>`. Without stripping the guard the
    // last name parses as `invoices.approve,web`, matches nothing in the map,
    // and the route silently loses its requirement.
    expect(scannedAbilities(['role_or_permission:admin|invoices.approve,web']))
        ->toBe(['admin', 'invoices.approve']);
});

it('resolves a host defined alias for an authorization middleware', function (): void {
    /*
     * Recognising only the literal strings `can:` and `permission:` makes the
     * scanner defeatable by an alias — and an alias is exactly what a host
     * writes when it wraps or renames middleware. Resolution goes through the
     * router's own alias table, so whatever the host called it, the class
     * underneath is what decides.
     */
    app('router')->aliasMiddleware('perm', Spatie\Permission\Middleware\PermissionMiddleware::class);

    expect(scannedAbilities(['perm:invoices.approve']))->toBe(['invoices.approve']);
});

it('resolves a host defined alias for the Laravel authorize middleware', function (): void {
    app('router')->aliasMiddleware('gatecheck', Illuminate\Auth\Middleware\Authorize::class);

    expect(scannedAbilities(['gatecheck:invoices.approve']))->toBe(['invoices.approve']);
});

it('does not treat an unrelated alias as an authorization middleware', function (): void {
    app('router')->aliasMiddleware('tenant', Illuminate\Auth\Middleware\Authenticate::class);

    expect(scannedAbilities(['tenant:invoices.approve']))->toBe([]);
});

it('reads what Route::can() compiles to', function (): void {
    Illuminate\Support\Facades\Route::post('/probe-can', fn (): string => 'ok')->can('invoices.approve');

    $route = collect(app('router')->getRoutes()->getRoutes())
        ->firstOrFail(fn (Illuminate\Routing\Route $candidate): bool => $candidate->uri() === 'probe-can');

    expect(app(RouteAbilityScanner::class)->abilitiesFor($route))->toContain('invoices.approve');
});
