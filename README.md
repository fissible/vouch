# Vouch

**Vouch** — proves who someone is, and how well. What they may do stays yours.

Vouch is Laravel authentication with password, OTP, MFA, and recorded session
assurance behind one policy engine. It orchestrates authentication factors and
step-up; it does not reimplement their cryptography or protocols.

Vouch is not an authorization package, token storage, or a UI. Your application
or its authorization package decides who may act; Vouch records how strongly
that person authenticated and can require a stronger session for that action.
Token issuance and token assurance are planned for 2.4, and presentation remains
the host application's responsibility. OIDC and federation are not planned.

## Requirements and maturity

Vouch requires PHP ^8.4 and Laravel 13 components (`illuminate/*` ^13.0). It
is pre-1.0 software: account lifecycle and assurance work ships in Phase 2.3,
the token-issuance gate is planned for 2.4, and standard UI adapters are Phase
3 work. See [the roadmap](PROJECT.md) for those phases.

Its account-lifecycle services cover identifier verification, credential
recovery, first-credential enrollment, and credential self-service. The host
still supplies presentation and application policy.

## Install and adopt

Install the package:

```sh
composer require fissible/vouch
```

Publish the configuration and migrations, then configure the package before
enabling login:

```sh
php artisan vendor:publish --tag=vouch-config
php artisan vendor:publish --tag=vouch-migrations
php artisan migrate
php artisan vouch:doctor
```

Before adding an assurance map or a direct assurance route, set
`VOUCH_STEP_UP_URL` to the host's routeable step-up presentation. Vouch does
not ship a step-up page. If an interactive request is refused and this value is
unset, Vouch deliberately throws a `RuntimeException` (a 500 response) rather
than redirecting a browser to its POST-only endpoint.

`vouch:doctor` checks adoption readiness as aggregate state; it never accepts
an identifier. Before login is live, verify identifier control through
`IdentifierVerifier`, bind real `OtpDelivery` and `DeliveryEconomics`
implementations, and run a durable asynchronous queue worker for
`vouch.otp.queue`. If CAPTCHA escalation is enabled, bind `CaptchaVerifier` as
well. The full prerequisite staircase, queue operation, and maintenance commands
are in [the operations guide](docs/operations.md).

## Compose authorization with assurance

Vouch deliberately leaves authorization to the host. For a host using
`spatie/laravel-permission`, the authorization middleware decides whether the
user has `invoices.approve`; Vouch's ability map says that this same ability
needs an `aal2` session. The route uses the host package's permission rule; the
map is central, so the assurance requirement is not repeated on each route.

Laravel 11+ hosts register Spatie's middleware alias themselves, for example in
`bootstrap/app.php`:

```php
use Illuminate\Foundation\Configuration\Middleware;

->withMiddleware(function (Middleware $middleware): void {
    $middleware->alias([
        'permission' => \Spatie\Permission\Middleware\PermissionMiddleware::class,
    ]);
})
```

```php
use App\Http\Controllers\ApproveInvoiceController;
use Illuminate\Support\Facades\Route;

Route::post('/invoices/{invoice}/approve', ApproveInvoiceController::class)
    ->middleware(['permission:invoices.approve']);
```

Spatie also ships a static helper that skips the alias entirely, which is worth
knowing if you would rather not claim the generic name `permission` in your
application's alias table:

```php
use Spatie\Permission\Middleware\PermissionMiddleware;

Route::post('/invoices/{invoice}/approve', ApproveInvoiceController::class)
    ->middleware([PermissionMiddleware::using('invoices.approve')]);
```

Vouch reads either form: the ability names come from the middleware parameters
on the matched route, and the alias is resolved through the router's own table.

```php
// Published Vouch configuration
'assurance_requirements' => [
    'invoices.approve' => 'aal2',
],
```

The package's `vouch.ability` middleware reads the authorization declarations
on the matched route and applies the strongest mapped requirement. It only
refuses or sends a browser to the configured `vouch.step_up.presentation_url`;
it never grants permission. This means you can use the same map with plain
Laravel Gates, Spatie permission middleware, or another authorization system
that exposes ability names on routes.

## Enforcement boundary

Vouch adds `vouch.ability` to the `web` and `api` middleware groups only. A
protected route in another or custom group must add `vouch.ability` explicitly,
or it is not covered by route enforcement. Run `php artisan vouch:assurance-map`
and inspect its `enforced_groups` field after configuring middleware, rather
than assuming a host's group is protected.

For a direct requirement on one route or group that is not derived from an
ability map, use the `vouch.assurance` alias, for example
`->middleware('vouch.assurance:aal2')`. It has the same presentation-URL
prerequisite as the map middleware.

The `Gate` hook is defense in depth, not the enforcement point. An earlier
`Gate` hook can grant an ability and bypass a later hook, so only the route
middleware can enforce the mapped assurance before that grant short-circuits
the check. The measured package-specific paths and their limits are documented
in the [authorization integration survey](docs/authorization-integration-survey.md).

For an authenticated request with no Vouch session, a mapped route returns a
403 response with `insufficient_assurance`; it does not evaluate a bearer token
or fail open. That remains the boundary until 2.4 adds token assurance.

## Strict maps

Set `vouch.assurance_strict` only after listing the host's intentional ability
vocabulary in `vouch.declared_abilities`. Strict mode cannot use
`Gate::abilities()` for that list: it is empty at boot for abilities defined
only at runtime, and it does not enumerate policy methods or database-backed
permissions. A host that defines an ability solely with `Gate::define` must
still list it in `vouch.declared_abilities` when strict mode is enabled.

## Host integration blind spots

`php artisan vouch:assurance-map --json` reports
`user_model_routes_to_gate`. Treat a false result as a coverage warning: a
model using Bouncer's `Authorizable` trait can silently take over `can()` and
stop that method reaching the Gate, without an error. The report can expose
that model seam, but it cannot detect `Bouncer::runBeforePolicies()` at all.
That switch moves Bouncer's grant into its before slot, where it can bypass a
later deny-only hook; keep the route middleware as the enforcement boundary.

See [operations](docs/operations.md) for adoption and runtime operation, and
the [authorization integration survey](docs/authorization-integration-survey.md)
for the measured Spatie, Bouncer, and Gate behavior behind these limits.
