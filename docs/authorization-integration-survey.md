# Authorization integration survey (2.3d Task 5a)

Measured against `spatie/laravel-permission` 8.3.0 and `silber/bouncer` v1.0.4
on Laravel 13, installed as `require-dev`. Both declare `illuminate/* ^13.0`,
so both install alongside Vouch without a version conflict.

This exists because an earlier draft asserted that a central `Gate::before`
hook would cover every integration. That was an assumption. The measured
answer is narrower, and in one respect the assumption is unsafe rather than
merely incomplete.

**Status: complete.** Dispatch and ordering semantics below are established
from source; everything the source could not settle was settled by executable
probe. The probes are committed under `tests/Authorization/` and run in the
suite, so a package upgrade that invalidates a finding fails a test rather than
silently rotting this document.

| Probe | Question | File |
|---|---|---|
| 1 | Which `Gate::before` hooks exist, in what order, under each provider discovery order? | `GateHookRegistrationProbeCase` + `BouncerFirstGateHookTest` / `SpatieFirstGateHookTest` |
| 1b | Which of Bouncer's two slots is live? | `BouncerSlotProbeTest` |
| 2 | Which `can()` does a user model actually call? | `UserModelCanResolutionTest` |

## What routes through `Gate`

| API | Reaches `Gate`? | Evidence |
|---|---|---|
| `$user->can()` on a plain Laravel user | yes | probe 2 |
| `$user->can()` on a spatie `HasRoles` user | yes | probe 2 — spatie never declares `can()` |
| `$user->can()` via Bouncer's `Authorizable` trait | **no** | probe 2 — goes straight to the Clipboard |
| `$user->canAny()` on **any** of the above | yes | probe 2 — Bouncer does not override `canAny()` |
| `Gate::allows()` / `denies()` / `authorize()` | yes | by definition |
| `@can` Blade directive | yes | compiles to a Gate check |
| Policy methods | yes | resolved by `callAuthCallback()` |
| spatie `PermissionMiddleware` | yes | calls `$user->canAny()` — `PermissionMiddleware.php:38` |
| spatie `RoleMiddleware` | **no** | calls `$user->hasAnyRole()` — `RoleMiddleware.php:38` |
| spatie `RoleOrPermissionMiddleware` | **partly** | permission branch reaches the Gate; role branch does not |
| spatie `$user->hasPermissionTo()` | no | model method, never enters the Gate |
| `Bouncer::can()` | yes | delegates to the Gate |

Two consequences that a per-package summary would hide:

- **spatie is split by middleware, and by config.** The permission path is
  enforceable and the role path is not, so an ability-keyed requirement never
  sees a `role:admin` route. The split also depends on
  `register_permission_check_method` being left at its default.
- **Bouncer is split by method, not by model.** Its trait overrides exactly
  `can`, `cant` and `cannot`. `canAny()` is untouched, so the same model that
  is unenforceable through `can()` is enforceable through `canAny()` — which is
  the method spatie's own `PermissionMiddleware` calls.

### Trait resolution (probe 2)

Measured, because it depends on PHP's trait precedence rather than on any call
site:

| Model composition | `can()` resolves to | Compiles? |
|---|---|---|
| stock `Illuminate\Foundation\Auth\User` | Gate | yes |
| `+ Spatie\...\HasRoles` | Gate | yes |
| `+ Silber\...\Authorizable` | **Clipboard** | yes — **silently** |
| `+ HasRoles + Silber\...\Authorizable` | **Clipboard** | yes — **silently** |
| `+ Illuminate\...\Authorizable + Silber\...\Authorizable` | — | **no — fatal** |
| the same pair with explicit `insteadof` | whichever `insteadof` names | yes |

The silent case is the important one, and it is the common one. A host follows
Bouncer's install instructions and adds its trait to a model that extends
`Illuminate\Foundation\Auth\User`. The parent already uses Illuminate's
`Authorizable`, and **a trait used in the child wins over an inherited method**,
so PHP reports nothing. The model's `can()` stops reaching the Gate with no
compile-time signal and no runtime error.

The fatal case only arises when both `Authorizable` traits are named in the
same `use` clause:

```
PHP Fatal error: Trait method Silber\Bouncer\Database\Concerns\Authorizable::can
has not been applied as Both::can, because of collision with
Illuminate\Foundation\Auth\Access\Authorizable::can
```

Note whose collision that is. It is **Illuminate's trait against Bouncer's**,
not one package against the other — spatie is not party to it, and a model
combining spatie and Bouncer compiles cleanly with Bouncer's `can()` winning.
An earlier draft of this survey described it as a three-way package collision;
that was wrong.

Explicit aliasing resolves it in the enforceable direction while keeping
Bouncer's check reachable:

```php
use BouncerAuthorizable, HasRoles, IlluminateAuthorizable {
    IlluminateAuthorizable::can insteadof BouncerAuthorizable;
    BouncerAuthorizable::can as bouncerCan;
}
```

## The ordering hazard

Both packages register a `Gate::before` hook, by different mechanisms:

- spatie registers through `callAfterResolving(Gate::class)`
  (`PermissionRegistrar::registerPermissions()`, returning `true` on a held
  permission — `PermissionRegistrar.php:121`)
- Bouncer resolves the Gate during its own boot and registers directly
  (`Guard::registerAt()`, which adds both a `before` and an `after` —
  `Guard.php:98`)

Laravel resolves multiple hooks as follows:

- `callBeforeCallbacks()` iterates in **registration order** and returns the
  first non-null result (`Gate.php:560`). A grant short-circuits everything
  after it.
- `callAfterCallbacks()` still runs, but assigns with `$result ??= $afterResult`
  (`Gate.php:589`). It **cannot override** a non-null result.

Probe 1 confirms both dispatch rules directly, and settles the two runtime
questions the source could not.

### Both hooks register, under either order

An earlier draft predicted that spatie's hook might never register when a
provider that resolves the Gate — Bouncer does — boots first, since
`afterResolving` fires on resolution and a singleton resolves once. **That
prediction is false.** `ServiceProvider::callAfterResolving()` also invokes the
callback immediately when `$app->resolved($name)` is already true
(`Support/ServiceProvider.php:310-317`), so the hook lands either way. Probe 1
asserts the full ordered list under both discovery orders; registration order
simply follows provider boot order.

### Bouncer's hook is inert by default

`Guard::$slot` defaults to **`'after'`** (`Guard.php:28`). Bouncer registers a
callback in both slots, but each returns early unless it is the active one. So
out of the box a Bouncer grant arrives in the *after* slot, where `??=` can only
fill in an undecided check — it **cannot** bypass a deny-only `before` hook.
`Bouncer::runBeforePolicies()` flips the slot, and then it can. Probe 1b
measures both settings.

This narrows the hazard relative to the earlier draft, which read the
registration list and concluded Bouncer was always in the `before` path.

### spatie's hook is the live hazard, and it fires on exactly the protected case

spatie's `before` hook has no such switch: it returns `true` whenever the user
holds the permission. So a deny-only hook registered after it is bypassed
precisely when the user **does** hold the ability — which is the only case an
assurance requirement exists to constrain. A user who lacks the permission is
denied by spatie anyway; a user who holds it never reaches the assurance check.
It does not degrade at the margin. It fails open at the center.

### A hook Vouch registers lands last

Probe 1 measures the position a provider booting after both packages receives:
**last**, under either discovery order — the one slot a grant short-circuits.
Vouch cannot fix this by registering earlier. Provider order comes from
`PackageManifest`, i.e. from `installed.json`, which Vouch does not control; a
host can override it explicitly, but a package cannot require that.

**A `Gate::before` hook alone is therefore not a sufficient enforcement
point.** That is stronger than "incomplete coverage": it fails open in exactly
the configuration the map exists to protect.

## What is enumerable for a strict mode

`Gate::abilities()` returns only explicitly `define()`d abilities
(`Gate.php:891`). It does not enumerate policy methods, spatie permissions, or
Bouncer abilities — the latter two live in the database.

Complete "unknown ability at boot" detection therefore requires a
**host-declared list**. Package database records can supply supplemental
diagnostics, but they are incomplete and cannot be the contract.

## Redirecting from an authorization callback

Not a viable integration boundary, for a narrower reason than "unsupported".

Returning a `RedirectResponse` from a Gate callback is actively **unsafe**: it
is truthy, so the Gate treats it as *allow*. A callback can technically throw
`redirect(...)->throwResponse()`, and a host exception renderer can redirect an
`AuthorizationException`. But neither generalizes: boolean `Gate::allows()`
checks never render exceptions, non-HTTP callers have nothing to redirect, and
the direct Bouncer-trait path above never reaches the callback.

Interactive step-up therefore belongs in middleware or host exception
rendering, not in the callback.

## Consequences for 5b

1. **Enforcement runs in route middleware.** The map cannot rely on a
   `Gate::before` hook: registered last, it is bypassed by a spatie grant on
   exactly the requests it is meant to constrain. The Gate hook ships as
   defense in depth, not as the primary mechanism.
2. **Coverage is stated per API, not per package.** Both packages are partly
   covered and partly invisible, and Bouncer's coverage is per *method*.
3. **Typo detection is bounded by a host-declared ability list.**
4. **Redirecting from the callback is off the table**, so interactive step-up
   runs at the middleware layer via `Vouch::stepUp()`.
5. **Two host configurations must be named in the documentation**, because
   neither is detectable from inside Vouch with any reliability: a model that
   took Bouncer's `can()` silently, and `Bouncer::runBeforePolicies()`. The
   inspection command shipped for item 3 is the natural place to report them.
