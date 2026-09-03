# Vouch

**Vouch** — authenticates your users to the degree you need. What they may do stays yours.

Vouch is Laravel authentication with password, OTP, MFA, and recorded session
assurance behind one policy engine. It orchestrates authentication factors and
step-up; it does not reimplement their cryptography or protocols.

Vouch is not an authorization package, token storage, or a UI. Your application
or its authorization package decides who may act; Vouch records how strongly
that person authenticated and can require stronger session or bearer-token
assurance for that action. Presentation remains the host application's
responsibility. OIDC and federation are not planned.

## Requirements and maturity

Vouch requires PHP ^8.4 and Laravel 13 components (`illuminate/*` ^13.0). It
is pre-1.0 software: account lifecycle and session assurance ship in Phase 2.3,
token issuance and assurance in Phase 2.4, and standard UI adapters are Phase
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

The shipped `NistAssuranceVocabulary` caps at `aal2`: `AssuranceFacts` carries
no hardware-binding evidence from which it could derive `aal3`. An ability map
or `vouch.assurance` requirement at `aal3` is therefore unreachable under the
shipped vocabulary; it always refuses requests silently and permanently. A
host should require `aal2` instead, or capture hardware binding and implement
its own `AssuranceVocabulary` to derive and emit `aal3`.

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
403 response with `insufficient_assurance`; the ability map is session
assurance, not a bearer-token fallback. In 2.4, bearer-token assurance is
enforced by the separate token gate below.

## Token assurance gate

Vouch adds `vouch.token` to the host's `web` and `api` middleware groups. The
group installation applies its default `aal1` requirement to tokens claimed by
a registered issuer; add `vouch.token` explicitly to another or custom group.
For a stricter route requirement, use the alias arguments
`->middleware('vouch.token:aal2,PT15M')`: the first argument is the assurance
level and the optional second argument is an ISO-8601 `max_age` duration.

The token gate ships in `observe` mode (`VOUCH_TOKEN_GATE_MODE=observe`). It
allows traffic but logs every token it would refuse with `issuer_key` and
`token_key`, never the plaintext token. Pre-existing tokens are deliberately
not backfilled. Install Vouch, watch those log records, reissue the affected
tokens through `Vouch::issueToken`, then set
`VOUCH_TOKEN_GATE_MODE=enforce` after the log goes quiet. The only valid modes
are `observe` and `enforce`; a typo in `VOUCH_TOKEN_GATE_MODE` throws a loud
configuration error instead of silently disarming the gate.

The Sanctum boundary is intentional: Vouch writes assurance only for tokens
issued through `Vouch::issueToken`; a direct Sanctum `createToken()` bypasses
that ceremony and is default-denied once enforcement is armed. Existing tokens
cannot safely be inferred or backfilled—revoke or drop and recreate them through
the Vouch issuer after the observe log identifies them. A machine token is not a
low-assurance human token: it is recorded as a machine actor and only satisfies
routes whose policy permits that actor class. Human assurance failures use the
RFC 9470 insufficient-user-authentication response; unknown, malformed, and
machine-on-human-route tokens intentionally collapse to RFC 6750 `invalid_token`
so the wire response does not reveal which record exists.

Run `php artisan vouch:audit-tokens` after adopting the issuer. It scans the
explicit `vouch.audit.paths` surface (default `app` and `routes`) with PHP's
lexer, reports direct issuance and named unresolved seams, and reads coverage
from the live router. `--strict` is deliberately noisy and opt-in: it fails on
an unallowlisted site, unresolved source seam, or malformed/stale allowlist, but
never an uncovered route because only the host knows which routes should gate
tokens. Allowlist entries require a rationale and accountable owner.

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

The morph map supplies the provider half of every persisted `SubjectKey`.
Changing, renaming, removing, or registering a morph map after sessions or
tokens exist changes what their stored provider means: signed-in users are
refused and must re-authenticate, and issued tokens stop authorizing. Vouch
does not migrate or rewrite the stored provider, so removing the changed map
restores old records; plan a morph-map change like an application-key rotation.

See [operations](docs/operations.md) for adoption and runtime operation, and
the [authorization integration survey](docs/authorization-integration-survey.md)
for the measured Spatie, Bouncer, and Gate behavior behind these limits.
