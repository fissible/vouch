# Authorization integration survey (2.3d Task 5a)

Measured against `spatie/laravel-permission` 8.3.0 and `silber/bouncer` v1.0.4
on Laravel 13, installed as `require-dev`. Both declare `illuminate/* ^13.0`,
so both install alongside Vouch without a version conflict.

This exists because an earlier draft asserted that a central `Gate::before`
hook would cover every integration. That was an assumption. The measured
answer is narrower, and in one respect the assumption is unsafe rather than
merely incomplete.

**Status: partial.** The dispatch and ordering semantics below are established
from source and are load-bearing. Two questions are *not* yet settled and are
listed at the end as required probes before 5b's design is fixed.

## What routes through `Gate`

| API | Reaches `Gate`? | Evidence |
|---|---|---|
| `$user->can()` on a plain Laravel user | yes | `Authorizable` delegates to the Gate |
| `Gate::allows()` / `denies()` / `authorize()` | yes | by definition |
| `@can` Blade directive | yes | compiles to a Gate check |
| Policy methods | yes | resolved by `callAuthCallback()` |
| spatie `PermissionMiddleware` | yes | calls `$user->canAny()` — `PermissionMiddleware.php:38` |
| spatie `RoleMiddleware` | **no** | calls `$user->hasAnyRole()` — `RoleMiddleware.php:38` |
| spatie `RoleOrPermissionMiddleware` | **partly** | permission branch reaches the Gate; role branch does not |
| spatie `$user->hasPermissionTo()` | no | model method, never enters the Gate |
| `Bouncer::can()` | yes | delegates to the Gate |
| `$user->can()` via Bouncer's `Authorizable` trait | **no** | calls the Clipboard directly — `Database/Concerns/Authorizable.php:17` |

Two consequences that a per-package summary would hide:

- **spatie is split by middleware, and by config.** The permission path is
  enforceable and the role path is not, so an ability-keyed requirement never
  sees a `role:admin` route. The split also depends on
  `register_permission_check_method` being left at its default.
- **Bouncer is split by which `can()` a user model inherits.** Bouncer's
  `Authorizable` trait overrides `can`/`cant`/`cannot` and bypasses the Gate.
  A model cannot simply `use` all three packages' traits: they conflict on
  those names and require explicit `insteadof`/`as` resolution, and whichever
  method wins decides whether the call is enforceable at all.

## The ordering hazard

Both packages install a `Gate::before` hook, but by different mechanisms:

- spatie registers through `afterResolving(Gate::class)`
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

So a deny-only `Gate::before` hook is bypassed whenever an earlier `before`
hook grants, and `Gate::after` cannot recover the deny.

**A `Gate::before` hook alone is therefore not a sufficient enforcement
point.** That is stronger than "incomplete coverage": it fails open in exactly
the configuration the map exists to protect.

The mechanism difference matters too. Because spatie registers via
`afterResolving`, a provider that resolves the Gate earlier — Bouncer does —
can mean spatie's callback is registered against an already-resolved singleton
and never runs at all. This installation's `installed.json` orders Bouncer
first, so the effective combined setup may carry Bouncer's hook and no spatie
Gate hook. That is a probe target, not a settled fact.

Vouch cannot guarantee its own registration order *autonomously* across
arbitrary host and package discovery. A host can control provider order
explicitly. The design conclusion is unchanged: ordering is not a safe primary
enforcement contract.

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
the direct spatie and Bouncer paths above never reach the callback.

Interactive step-up therefore belongs in middleware or host exception
rendering, not in the callback.

## Required probes before 5b

Source reading establishes dispatch and ordering. Two questions need
executable probes, because they depend on runtime resolution rather than call
sites:

1. **Effective combined registration.** With both packages installed, which
   `before` hooks actually exist, in what order, under each provider discovery
   order? The `afterResolving` interaction above predicts spatie's hook may be
   absent entirely.
2. **Trait resolution.** Build separate models, or one model with explicit
   `insteadof`/`as` aliases — not an unqualified three-trait model, which does
   not compile — and confirm which `can()` each configuration actually calls.

## Consequences for 5b

1. The map cannot rely on a `Gate::before` hook alone. Enforcement needs a
   point that runs before the authorization call — route middleware — with the
   Gate hook as defense in depth rather than the primary mechanism.
2. Coverage is stated per API, not per package. Both packages are partly
   covered and partly invisible.
3. Typo detection is bounded by a host-declared ability list.
4. Redirecting from the callback is off the table, so interactive step-up runs
   at the middleware layer via `Vouch::stepUp()`.
