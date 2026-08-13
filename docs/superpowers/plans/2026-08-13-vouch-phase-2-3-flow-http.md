# Vouch Phase 2.3 — Flow and HTTP Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the flow orchestrator, a JSON HTTP surface, session lifecycle, recovery-grace enforcement and interactive `RequireAssurance` — the first slice of vouch that can log anyone in.

**Architecture:** One endpoint drives a server-owned state machine. `AuthFlow` orchestrates and returns a typed `FlowResult`; a thin handler routes `Authenticated` to `SessionLifecycle` before the controller serializes anything. Transition legality stays in the kernel's `TransitionRules`, error disclosure stays in the kernel's `ErrorShaper`, and nothing HTTP-shaped crosses into the flow. Recovery-grace is an anonymous session carrying a server-side capability that authorizes only vouch's own grace routes.

**Tech Stack:** PHP 8.4, Laravel 13 (`illuminate/*` ^13.0), Orchestra Testbench ^11.0, Pest 3, PHPStan level 9 (Larastan).

## Global Constraints

Copied from the spec and from the still-binding rules of Phases 1, 2.1 and 2.2.

- **PHP `^8.4`.** `declare(strict_types=1);` in every PHP file.
- **`src/Kernel/` may depend only on `php` and `psr/clock`, and must not be modified.** This phase consumes kernel types; it never edits them and never adds a kernel method to make a test convenient. `tests/Arch/KernelBoundaryTest.php` is the enforcement.
- **No new production dependencies.**
- **All vouch timestamps are stored in UTC.**
- **PHPStan level 9 over `src` and `tests` must stay clean.** No `@phpstan-ignore`, no casts-to-silence, no widened types. Every prior task in this project held that line; where Larastan cannot narrow, use the established patterns — typed magic-property access on models, `assert()` in tests, `array_values()` on native variadics.
- **The raw host session ID is never persisted and never returned in a response.**
- **Drivers validate; they never evaluate policy. Nothing writes single-use state except the store.** 2.2's rules still bind.
- **`ErrorShaper` is the only component that may decide what a user-visible authentication error says.**
- **2.3 neither calls nor exposes `Factor::revoke()`.** Arch-tested. Last-factor protection does not exist yet, and a deletion surface without it is the lockout described in the spec.
- **No 2.3 path may reach `ErrorShaper`'s lockout carve-out.** `Outcome::Locked`,
  `AttemptState::Locked`, and any non-null `RetryPolicy` construction are **banned** from
  2.3-owned source — `src/Flow/`, `src/Http/`, `src/Sessions/`, `src/Recovery/`. This is an
  architecture scan (Task 9), not a convention. `ErrorShaper` discloses lockouts
  unconditionally, in full, under strict posture; that is safe only once 2.3b applies
  identical limits to existing and nonexistent identifiers. Until then any lockout path
  vouch could reach is an account-existence oracle with every kernel test green.
- **Conventional Commits. Commit by explicit path — never `git add -A`.**
- **Branch:** all work happens on `feat/vouch-2-3-flow-http`, branched from `main`.

---

## Preflight decision — resolve before Task 1

**This is a decision, not an implementation step, and it must be settled before any task runs.**

The spec states one unresolved asymmetry: `auth_sessions.recovery_grace_expires_at` is *written* from the application clock at grace creation, while every read evaluates it against `CURRENT_TIMESTAMP`. Skew therefore shifts the effective grace window rather than the nominal fifteen minutes.

Two acceptable resolutions. Pick one, record it in `PROJECT.md` with its reasoning, and implement only that one:

**(a) Write the deadline with each engine's database clock.** Interval arithmetic is not portable — MySQL uses `DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? SECOND)`, Postgres `CURRENT_TIMESTAMP + (? * INTERVAL '1 second')`, SQLite `datetime('now', ? || ' seconds')` — so this needs a per-driver expression, built once and covered by the three-engine matrix. Closes the seam completely: one clock writes and reads.

**(b) Document a bounded, tested skew policy.** Keep the application-clock write, state the maximum tolerated skew explicitly, and add a test that proves the effective window stays within that bound when the application clock is moved. Cheaper, and honest only if the bound is actually asserted rather than asserted-in-prose.

**Do not begin Task 1 with this open.** The same seam silently invalidated Phase 2.2's TOTP tests — they were green only while real time happened to sit before a frozen expiry — and it was caught by merge verification rather than by any test. Leaving it unresolved here means discovering it in production instead.

---

## Verified context

Established by reading the code before this plan was written. Do not re-derive; do not "fix" code that matches these.

| Fact | Consequence |
|---|---|
| `ErrorShaper::shape(ScreenSpec, Outcome, EnumerationPosture): ScreenSpec` carries a **precondition addressed to Phase 2**: its `Locked` carve-out discloses the message and `RetryPolicy` under *every* posture, and is safe only if rate limits apply identically to known and unknown identifiers. | 2.3 has no rate limiting, so **`ScreenBuilder` must never emit `Outcome::Locked`** — emitting it with a null `RetryPolicy` would be a lie. Carry the precondition to 2.3b in `PROJECT.md`; it is the difference between a strict posture and an account-existence oracle. |
| `Outcome` has exactly four cases: `IdentifierKnown`, `IdentifierUnknown`, `CredentialRejected`, `Locked`. | 2.3 uses the first three. |
| `ScreenSpec` is `final readonly` with public properties `step`, `offeredFactors`, `fields`, `challengePayload`, `errors`, `retry`. | `challengePayload` is `?array`, not a `ChallengePayload` object — the parent spec's §8.2 sketch differs from what Phase 1 shipped. Build against the code. |
| `FieldSpec(string $name, string $type, string $autocomplete, ?int $maxLength)`; `FactorOption(string $factorId, string $label, FactorStrength $strength, bool $isDefault)`; `RetryPolicy(?int $attemptsRemaining, ?DateTimeImmutable $lockedUntil)`. | Exact constructor shapes for `ScreenBuilder`. |
| `AssuranceLevel(string $acr, AssuranceFacts $facts)` with `satisfiesRecency(DateInterval, ClockInterface): bool`; `AssuranceVocabulary::name(AssuranceFacts): string`. | `RequireAssurance` compares via these, never by re-deriving an `acr` string. |
| `SessionBinding::for(string $hostSessionId): string` returns a 64-char HMAC keyed to `APP_KEY` and throws without one. | Task 1 makes the domain required and updates call sites. |
| `AttemptStore::transition(AuthAttempt, AttemptState, SingleUseMutation ...$mutations): TransitionOutcome`, throwing `ConflictingMutations`, `UnknownMutation`, `MisdirectedMutation`. | `AuthFlow` passes driver-returned mutations straight through. |
| `DatabaseAttemptStore::now()` returns `new Expression('CURRENT_TIMESTAMP')` and its docblock records the app/database clock seam. | Grace predicates follow the same convention. |
| `RevokedReason` cases: `logout`, `grace_expired`, `credential_changed`, `password_changed`, `admin_revoked`, `superseded`. | Task 7 writes `grace_expired` only under `revoked_at IS NULL`. |
| `AuthSession` exposes `isRecoveryGrace()` reading `recovery_grace_expires_at`, and 2.1 rotates bindings in place with a test that the row count stays at one. | Do not add a second row on rotation. |
| Contention tests use `DatabaseMigrations`, never `RefreshDatabase`, and skip on in-memory SQLite. `tests/TestCase.php` sets `busy_timeout` and deliberately does **not** set `journal_mode` — setting it broke the whole file-backed SQLite contention suite in 2.2. | Any new concurrency test follows the same shape. |
| MySQL implicitly commits on DDL, so `Schema::drop()` inside a `RefreshDatabase` transaction destroys the savepoint. | A test needing DDL uses `DatabaseMigrations` in its own file, as `tests/Database/EnrollmentGuardErrorsTest.php` does. |

---

## File structure

| File | Responsibility |
|---|---|
| `src/Sessions/BindingDomain.php` | Enum — `Session`, `Attempt`. The required domain argument. |
| `src/Sessions/SessionBinding.php` | Modified: domain becomes required. |
| `src/Flow/FlowRequest.php` | Framework-free input to the flow: handle, action, input, bound context, client IP/UA. |
| `src/Flow/FlowResult.php` + `Continuing.php` / `Authenticated.php` / `RecoveryGraceStarted.php` | The typed completion seam. |
| `src/Flow/AuthSuccess.php` | User ID, satisfied factors, assurance facts, bound-context key. No HTTP or session types. |
| `src/Flow/UnknownFlowResult.php` | `LogicException` for an unhandled variant. |
| `src/Flow/ScreenBuilder.php` | Builds `ScreenSpec`; the sole caller of `ErrorShaper` in Phase 2. |
| `src/Flow/AuthFlow.php` | The orchestrator. |
| `src/Sessions/SessionLifecycle.php` | The fail-closed rotation protocol. |
| `src/Http/FlowResultSerializer.php` | `FlowResult` → envelope array. |
| `src/Http/AuthController.php` | One action. |
| `src/Http/Middleware/ValidatesVouchSession.php` | Per-request authoritative read. |
| `src/Http/Middleware/RequireAssurance.php` | Interactive mode; comparison shared with 2.4's renderer. |
| `src/Recovery/GraceGuard.php` | Resolves active grace by binding, entirely in database time. |
| `src/Recovery/GraceController.php` | Enrollment and completion routes. |
| `routes/vouch.php` | Route definitions. |
| `src/VouchServiceProvider.php` | Modified: routes, middleware append, boot assertion. |
| `tests/Support/ReferenceRenderer/` | Test-only Blade consumer, never registered in production. |

---

## Task 1: `BindingDomain` and the `SessionBinding` amendment

**Files:**
- Create: `src/Sessions/BindingDomain.php`
- Modify: `src/Sessions/SessionBinding.php`
- Modify: `tests/Database/SessionsTest.php`, `tests/Database/PruneCommandTest.php` (18 call sites across the two)
- Test: `tests/Database/SessionBindingDomainTest.php`

**Interfaces:**
- Consumes: nothing
- Produces: `Fissible\Vouch\Sessions\BindingDomain` (enum, cases `Session` and `Attempt`); `SessionBinding::for(string $hostSessionId, BindingDomain $domain): string`

This is an amendment to Phase 2.1. The domain is **required**, not defaulted — a default is how an accidental cross-context derivation gets written silently and reviewed past. Every later task depends on `bound_context` and `session_binding` being different values for the same session.

- [ ] **Step 1: Write the failing test**

Create `tests/Database/SessionBindingDomainTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('derives a different value per domain for the same session', function (): void {
    /*
     * The whole point of the amendment. Without domain separation both columns
     * hold the same value, so a bound_context that escapes into a log or an
     * error message is immediately a valid lookup key into auth_sessions.
     */
    $sessionId = 'the-raw-host-session-id';

    expect(SessionBinding::for($sessionId, BindingDomain::Session))
        ->not->toBe(SessionBinding::for($sessionId, BindingDomain::Attempt));
});

it('stays stable within a domain', function (): void {
    expect(SessionBinding::for('abc', BindingDomain::Attempt))
        ->toBe(SessionBinding::for('abc', BindingDomain::Attempt));
});

it('never contains the raw session id, in either domain', function (): void {
    foreach (BindingDomain::cases() as $domain) {
        expect(SessionBinding::for('raw-id-must-not-appear', $domain))
            ->not->toContain('raw-id-must-not-appear')
            ->and(SessionBinding::for('raw-id-must-not-appear', $domain))->toHaveLength(64);
    }
});

it('still refuses to derive a binding with no APP_KEY', function (): void {
    config(['app.key' => null]);

    SessionBinding::for('abc', BindingDomain::Session);
})->throws(RuntimeException::class);

it('lists every binding domain exactly once', function (): void {
    // Pins the enum so a third domain cannot be added without a decision.
    expect(array_map(fn (BindingDomain $d): string => $d->value, BindingDomain::cases()))
        ->toBe(['session', 'attempt']);
});
```

- [ ] **Step 2: Run it and watch it fail**

Run: `vendor/bin/pest tests/Database/SessionBindingDomainTest.php`
Expected: FAIL — `BindingDomain` not found.

- [ ] **Step 3: Write `BindingDomain`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

/**
 * Which binding a derived value is for.
 *
 * Required rather than defaulted, deliberately. Two columns bind to the same
 * host session — auth_sessions.session_binding and auth_attempts.bound_context
 * — and if both derived the same value, one escaping into a log or an error
 * message would immediately be a valid lookup key for the other.
 *
 * A default would make that cross-context derivation something a future caller
 * can write silently and a reviewer can miss. Requiring the argument makes it
 * unwritable: the type system carries the rule rather than a docblock.
 */
enum BindingDomain: string
{
    /** auth_sessions.session_binding — an established session. */
    case Session = 'session';

    /** auth_attempts.bound_context — an in-progress authentication attempt. */
    case Attempt = 'attempt';
}
```

- [ ] **Step 4: Amend `SessionBinding`**

Keep the existing class docblock — its reasoning about bearer credentials is still exactly right — and add the domain. Replace the method:

```php
    public static function for(string $hostSessionId, BindingDomain $domain): string
    {
        $key = config('app.key');

        if (! is_string($key) || $key === '') {
            throw new RuntimeException(
                'Vouch requires APP_KEY to be set: it keys the session binding HMAC.',
            );
        }

        /*
         * The domain is part of the HMAC input, separated by a NUL byte so that
         * no domain/session-ID pair can be confused with another. Without the
         * separator, domain "sessiona" + id "bc" and domain "session" + id "abc"
         * would derive the same value.
         */
        return hash_hmac('sha256', $domain->value . "\0" . $hostSessionId, $key);
    }
```

Add `use` for `BindingDomain` — it is in the same namespace, so no import is needed.

- [ ] **Step 5: Update the 18 existing call sites**

`tests/Database/SessionsTest.php` and `tests/Database/PruneCommandTest.php` both call `SessionBinding::for($id)`. Every one of them is establishing or looking up an `auth_sessions` row, so every one becomes `SessionBinding::for($id, BindingDomain::Session)`. Add the import to both files.

Do **not** add a compatibility shim or a default to avoid this edit. The edit is the point.

- [ ] **Step 6: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Database/SessionBindingDomainTest.php tests/Database/SessionsTest.php tests/Database/PruneCommandTest.php`
Expected: PASS.

- [ ] **Step 7: Prove the domain is load-bearing**

```bash
cp src/Sessions/SessionBinding.php /tmp/sb.bak
```

Change the HMAC input back to `$hostSessionId` alone, ignoring the domain. The "derives a different value per domain" test must FAIL. If it passes, the assertion is not measuring separation. Restore:

```bash
cp /tmp/sb.bak src/Sessions/SessionBinding.php
vendor/bin/pest tests/Database/SessionBindingDomainTest.php   # green again
```

- [ ] **Step 8: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 9: Commit**

```bash
git add src/Sessions/BindingDomain.php src/Sessions/SessionBinding.php tests/Database/SessionBindingDomainTest.php tests/Database/SessionsTest.php tests/Database/PruneCommandTest.php
git commit -m "feat!: require a binding domain when deriving a session binding

Amends Phase 2.1. auth_attempts.bound_context and auth_sessions.session_binding
both bind to the same host session; deriving them identically would make an
escaped bound_context a valid session lookup key. The domain is required rather
than defaulted so a cross-context derivation is unwritable rather than merely
tested against."
```

---

## Task 2: The flow's value objects

**Files:**
- Create: `src/Flow/FlowRequest.php`, `src/Flow/AuthSuccess.php`, `src/Flow/FlowResult.php`, `src/Flow/Continuing.php`, `src/Flow/Authenticated.php`, `src/Flow/RecoveryGraceStarted.php`, `src/Flow/UnknownFlowResult.php`
- Test: `tests/Flow/FlowResultTest.php`
- Modify: `tests/Pest.php`

**Interfaces:**
- Consumes: `BindingDomain` (Task 1); kernel `ScreenSpec`, `SatisfiedFactor`, `AssuranceFacts`
- Produces:
  - `FlowRequest(?string $handle, ?string $action, array $input, string $boundContext, ?string $clientIp, ?string $clientUserAgent)` with `string(string $key): ?string`
  - `AuthSuccess(int $userId, list<SatisfiedFactor> $factors, AssuranceFacts $facts, string $acr, string $boundContext)` with `amr(): list<string>`
  - `FlowResult` interface; `Continuing(ScreenSpec $screen)`; `Authenticated(AuthSuccess $success, ScreenSpec $screen)`; `RecoveryGraceStarted(int $userId, string $boundContext, ScreenSpec $screen)`
  - `UnknownFlowResult extends LogicException` with `::for(FlowResult $result): self`

Every variant carries a `ScreenSpec` so the controller can always serialize something without inspecting state; the discriminator is the type, not the screen.

- [ ] **Step 1: Register the test directory**

In `tests/Pest.php`, add `'Flow'` to the Testbench list alongside `Database`, `Concurrency` and `Factors`. `tests/Secrets` stays absent — it is framework-free.

- [ ] **Step 2: Write the failing test**

Create `tests/Flow/FlowResultTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Flow\FlowResult;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Flow\UnknownFlowResult;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;

function blankScreen(AuthStep $step = AuthStep::Identify): ScreenSpec
{
    return new ScreenSpec($step, [], [], null, [], null);
}

function satisfied(string $id = 'password'): SatisfiedFactor
{
    return new SatisfiedFactor(
        factorId: $id,
        credentialId: '7',
        kind: FactorKind::Knowledge,
        strength: FactorStrength::Knowledge,
        isMultiFactor: false,
        userVerified: false,
        phishingResistant: false,
        authenticatorId: null,
        satisfiedAt: new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
    );
}

it('reads a string field, or null when absent or the wrong type', function (): void {
    // Input arrives from a request body; the flow must not trust its shape.
    $request = new FlowRequest(
        handle: null,
        action: 'submit',
        input: ['code' => '123456', 'nested' => ['not', 'a', 'string']],
        boundContext: 'binding',
        clientIp: null,
        clientUserAgent: null,
    );

    expect($request->string('code'))->toBe('123456')
        ->and($request->string('nested'))->toBeNull()
        ->and($request->string('missing'))->toBeNull();
});

it('derives the amr from the satisfied factors, in order', function (): void {
    $success = new AuthSuccess(
        userId: 7,
        factors: [satisfied('password'), satisfied('totp')],
        facts: AssuranceFacts::fromFactors([satisfied('password'), satisfied('totp')]),
        acr: 'aal2',
        boundContext: 'binding',
    );

    expect($success->amr())->toBe(['password', 'totp']);
});

it('carries a screen on every variant, so serialization never inspects state', function (): void {
    $success = new AuthSuccess(7, [satisfied()], AssuranceFacts::fromFactors([satisfied()]), 'aal1', 'b');

    expect((new Continuing(blankScreen()))->screen)->toBeInstanceOf(ScreenSpec::class)
        ->and((new Authenticated($success, blankScreen()))->screen)->toBeInstanceOf(ScreenSpec::class)
        ->and((new RecoveryGraceStarted(7, 'b', blankScreen(AuthStep::Enroll)))->screen)
        ->toBeInstanceOf(ScreenSpec::class);
});

it('names an unhandled variant rather than describing it vaguely', function (): void {
    /*
     * PHP has no sealed interfaces, which is why DatabaseAttemptStore throws
     * UnknownMutation rather than skipping a type it does not recognise. The
     * same hazard applies here, and the consequence is worse: falling through
     * on an unrecognised result would skip session rotation on a successful
     * authentication.
     */
    $rogue = new class implements FlowResult
    {
        public function screen(): void {}
    };

    expect(fn () => throw UnknownFlowResult::for($rogue))
        ->toThrow(UnknownFlowResult::class, $rogue::class);
});
```

- [ ] **Step 3: Run it and watch it fail**

Run: `vendor/bin/pest tests/Flow/FlowResultTest.php`
Expected: FAIL — `Fissible\Vouch\Flow\FlowRequest` not found.

- [ ] **Step 4: Write `FlowRequest`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

/**
 * Everything the flow needs from a request, with nothing HTTP-shaped in it.
 *
 * No Request, Response or Session type crosses into the flow. That is what lets
 * one core drive both the JSON surface and Phase 3's adapters, and what makes
 * AuthFlow testable without booting a router.
 *
 * $boundContext is the DERIVED binding, never the raw host session ID — see
 * BindingDomain. Callers pass SessionBinding::for($id, BindingDomain::Attempt).
 */
final readonly class FlowRequest
{
    /**
     * @param  array<string, mixed>  $input
     */
    public function __construct(
        public ?string $handle,
        public ?string $action,
        public array $input,
        public string $boundContext,
        public ?string $clientIp = null,
        public ?string $clientUserAgent = null,
    ) {}

    /**
     * Read a string field, or null when it is absent or the wrong type.
     *
     * $input arrives from a request body; its shape is not to be trusted. Same
     * contract as VerificationRequest::string() in 2.2.
     */
    public function string(string $key): ?string
    {
        $value = $this->input[$key] ?? null;

        return is_string($value) ? $value : null;
    }
}
```

- [ ] **Step 5: Write `AuthSuccess`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

/**
 * What a completed authentication established.
 *
 * Deliberately carries no HTTP or session object. SessionLifecycle receives
 * this and performs the rotation; the flow that produced it never touches a
 * session, which is what keeps the two testable apart.
 */
final readonly class AuthSuccess
{
    /**
     * @param  list<SatisfiedFactor>  $factors  Fresh evidence from THIS attempt.
     */
    public function __construct(
        public int $userId,
        public array $factors,
        public AssuranceFacts $facts,
        public string $acr,
        public string $boundContext,
    ) {}

    /**
     * The authentication methods, in the order they were satisfied.
     *
     * @return list<string>
     */
    public function amr(): array
    {
        return array_values(array_map(
            static fn (SatisfiedFactor $factor): string => $factor->factorId,
            $this->factors,
        ));
    }
}
```

- [ ] **Step 6: Write the result interface and its three variants**

`src/Flow/FlowResult.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

/**
 * The outcome of advancing an attempt.
 *
 * A typed result rather than a bare ScreenSpec. Returning only a screen would
 * force the controller to infer completion from screen contents — exactly the
 * branching on AuthStep that the HTTP boundary forbids — and would leave
 * session rotation with no explicit seam to hang from.
 */
interface FlowResult {}
```

`src/Flow/Continuing.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Screen\ScreenSpec;

/** The attempt advanced and wants another interaction. */
final readonly class Continuing implements FlowResult
{
    public function __construct(
        public ScreenSpec $screen,
    ) {}
}
```

`src/Flow/Authenticated.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Screen\ScreenSpec;

/**
 * Policy is satisfied. The session has NOT been rotated yet — that is
 * SessionLifecycle's job, and it happens before anything is serialized.
 */
final readonly class Authenticated implements FlowResult
{
    public function __construct(
        public AuthSuccess $success,
        public ScreenSpec $screen,
    ) {}
}
```

`src/Flow/RecoveryGraceStarted.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Screen\ScreenSpec;

/**
 * A recovery code opened the constrained capability.
 *
 * Distinct from Authenticated on purpose: the host guard is never invoked for
 * this result, and conflating the two is how a stolen recovery code would
 * become a broadly authenticated application session.
 */
final readonly class RecoveryGraceStarted implements FlowResult
{
    public function __construct(
        public int $userId,
        public string $boundContext,
        public ScreenSpec $screen,
    ) {}
}
```

- [ ] **Step 7: Write `UnknownFlowResult`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use LogicException;

/**
 * A FlowResult variant nothing knows how to handle.
 *
 * PHP has no sealed interfaces, so a future variant can be added without every
 * handler learning about it. Falling through to "serialize whatever screen we
 * have" would silently skip session rotation on a successful authentication —
 * the user would appear logged in and hold no record. Throwing is the same
 * discipline DatabaseAttemptStore applies to UnknownMutation.
 */
final class UnknownFlowResult extends LogicException
{
    public static function for(FlowResult $result): self
    {
        return new self(sprintf(
            'No handler for FlowResult variant %s. Every variant must be handled '
            . 'explicitly; falling through would skip session rotation on success.',
            $result::class,
        ));
    }
}
```

- [ ] **Step 8: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Flow/FlowResultTest.php`
Expected: PASS, 4 tests.

- [ ] **Step 9: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 10: Commit**

```bash
git add src/Flow tests/Flow/FlowResultTest.php tests/Pest.php
git commit -m "feat: add the flow's value objects and the typed FlowResult seam

Every variant carries a ScreenSpec so serialization never inspects state, and
an unhandled variant throws rather than falling through -- the same reasoning
as UnknownMutation, with a worse consequence: a skipped session rotation on a
successful authentication."
```

---

## Task 3: `ScreenBuilder` — the sole disclosure path

**Files:**
- Create: `src/Flow/ScreenBuilder.php`
- Test: `tests/Flow/ScreenBuilderTest.php`

**Interfaces:**
- Consumes: kernel `ScreenSpec`, `AuthStep`, `FactorOption`, `FieldSpec`, `ErrorShaper`, `Outcome`, `EnumerationPosture`; `FactorRegistry` (2.2)
- Produces:
  - `ScreenBuilder::__construct(ErrorShaper $shaper, FactorRegistry $registry)`
  - `identify(EnumerationPosture $posture): ScreenSpec`
  - `challenge(string $factorId, EnumerationPosture $posture, ?array $payload = null): ScreenSpec`
  - `refused(AuthStep $step, Outcome $outcome, EnumerationPosture $posture, string $factorId = null): ScreenSpec`

**Two absolute rules for this class.** It is the only place in Phase 2 that constructs a user-visible authentication error, and every one goes through `ErrorShaper`. And it **must never emit `Outcome::Locked`** — `ErrorShaper` discloses that case in full under every posture including strict, which is safe only when rate limits apply identically to known and unknown identifiers. 2.3 has no rate limiting, so `Locked` cannot honestly occur; emitting it with a null `RetryPolicy` would fabricate a lockout nobody measured.

- [ ] **Step 1: Write the failing test**

Create `tests/Flow/ScreenBuilderTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\ScreenBuilder;
use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\FactorOption;
use Fissible\Vouch\Kernel\Screen\FieldSpec;

function builder(): ScreenBuilder
{
    return app(ScreenBuilder::class);
}

it('offers an identifier field on the identify screen', function (): void {
    $screen = builder()->identify(EnumerationPosture::Friendly);

    expect($screen->step)->toBe(AuthStep::Identify)
        ->and($screen->fields)->toHaveCount(1)
        ->and($screen->fields[0])->toBeInstanceOf(FieldSpec::class)
        ->and($screen->fields[0]->name)->toBe('identifier')
        ->and($screen->errors)->toBe([])
        ->and($screen->retry)->toBeNull();
});

it('offers every registered factor on a challenge screen', function (): void {
    $screen = builder()->challenge('password', EnumerationPosture::Friendly);

    expect($screen->step)->toBe(AuthStep::Challenge)
        ->and($screen->offeredFactors)->not->toBeEmpty()
        ->and($screen->offeredFactors[0])->toBeInstanceOf(FactorOption::class);
});

it('marks exactly one offered factor as the default', function (): void {
    // A screen with two defaults, or none, is a rendering ambiguity every
    // adapter would resolve differently.
    $defaults = array_filter(
        builder()->challenge('password', EnumerationPosture::Friendly)->offeredFactors,
        static fn (FactorOption $option): bool => $option->isDefault,
    );

    expect($defaults)->toHaveCount(1);
});

it('never discloses which of the two identifier outcomes occurred under strict posture', function (): void {
    /*
     * The enumeration boundary. Under strict posture an unknown identifier and
     * a rejected credential must be indistinguishable in the rendered screen,
     * exactly as they are indistinguishable in the HTTP status.
     */
    $unknown = builder()->refused(AuthStep::Identify, Outcome::IdentifierUnknown, EnumerationPosture::Strict);
    $rejected = builder()->refused(AuthStep::Identify, Outcome::CredentialRejected, EnumerationPosture::Strict);

    expect($unknown->errors)->toBe($rejected->errors);
});

it('does distinguish them under friendly posture', function (): void {
    // Proves the strict assertion above is measuring posture, not measuring a
    // builder that always returns the same message.
    $unknown = builder()->refused(AuthStep::Identify, Outcome::IdentifierUnknown, EnumerationPosture::Friendly);
    $rejected = builder()->refused(AuthStep::Identify, Outcome::CredentialRejected, EnumerationPosture::Friendly);

    expect($unknown->errors)->not->toBe($rejected->errors);
});

it('never emits a retry policy in 2.3', function (): void {
    // Rate limiting is 2.3b. A fabricated retry state would report something
    // nobody measured.
    foreach ([Outcome::IdentifierUnknown, Outcome::CredentialRejected] as $outcome) {
        expect(builder()->refused(AuthStep::Challenge, $outcome, EnumerationPosture::Strict)->retry)
            ->toBeNull();
    }
});

it('refuses to shape a locked outcome', function (): void {
    /*
     * ErrorShaper discloses Locked in full under every posture, which is safe
     * only when rate limits apply identically to known and unknown identifiers.
     * 2.3 has no rate limiting, so nothing can honestly be locked -- and a
     * Locked screen with a null RetryPolicy would be a fabricated lockout.
     * 2.3b removes this guard when it can satisfy the precondition.
     */
    builder()->refused(AuthStep::Challenge, Outcome::Locked, EnumerationPosture::Strict);
})->throws(LogicException::class);
```

- [ ] **Step 2: Run it and watch it fail**

Run: `vendor/bin/pest tests/Flow/ScreenBuilderTest.php`
Expected: FAIL — `ScreenBuilder` not found.

- [ ] **Step 3: Write `ScreenBuilder`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\ErrorShaper;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\FactorOption;
use Fissible\Vouch\Kernel\Screen\FieldSpec;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;
use LogicException;

/**
 * Builds the screen a client renders, and is the ONLY component in Phase 2 that
 * may construct a user-visible authentication error.
 *
 * Every error goes through the kernel's ErrorShaper under the tenant's posture.
 * 2.2's drivers report truthfully — NoCredential distinct from Mismatch,
 * BindingMismatch distinct from both — and this is where that truth is filtered
 * for disclosure. Two components deciding disclosure would make the strict
 * posture guarantee unverifiable, which is why there is one.
 */
final readonly class ScreenBuilder
{
    public function __construct(
        private ErrorShaper $shaper,
        private FactorRegistry $registry,
    ) {}

    public function identify(EnumerationPosture $posture): ScreenSpec
    {
        return new ScreenSpec(
            step: AuthStep::Identify,
            offeredFactors: [],
            fields: [new FieldSpec('identifier', 'text', 'username', 255)],
            challengePayload: null,
            errors: [],
            retry: null,
        );
    }

    /**
     * @param  array<string, mixed>|null  $payload
     */
    public function challenge(string $factorId, EnumerationPosture $posture, ?array $payload = null): ScreenSpec
    {
        return new ScreenSpec(
            step: AuthStep::Challenge,
            offeredFactors: $this->offeredFactors($factorId),
            fields: [new FieldSpec('code', 'text', 'one-time-code', 64)],
            challengePayload: $payload,
            errors: [],
            retry: null,
        );
    }

    /**
     * A refusal, shaped for disclosure.
     *
     * @throws LogicException when handed Outcome::Locked.
     */
    public function refused(
        AuthStep $step,
        Outcome $outcome,
        EnumerationPosture $posture,
        ?string $factorId = null,
    ): ScreenSpec {
        if ($outcome === Outcome::Locked) {
            throw new LogicException(
                'ScreenBuilder cannot shape Outcome::Locked in Phase 2.3. ErrorShaper '
                . 'discloses Locked in full under every posture, which is safe only when '
                . 'rate limits apply identically to known and unknown identifiers — and '
                . '2.3 ships no rate limiting, so nothing can honestly be locked. Emitting '
                . 'it with a null RetryPolicy would fabricate a lockout nobody measured. '
                . 'Phase 2.3b removes this guard once it can satisfy the precondition.',
            );
        }

        $base = new ScreenSpec(
            step: $step,
            offeredFactors: $factorId === null ? [] : $this->offeredFactors($factorId),
            fields: $step === AuthStep::Identify
                ? [new FieldSpec('identifier', 'text', 'username', 255)]
                : [new FieldSpec('code', 'text', 'one-time-code', 64)],
            challengePayload: null,
            errors: [],
            retry: null,
        );

        return $this->shaper->shape($base, $outcome, $posture);
    }

    /**
     * @return list<FactorOption>
     */
    private function offeredFactors(string $defaultFactorId): array
    {
        return array_values(array_map(
            fn (Factor $factor): FactorOption => new FactorOption(
                factorId: $factor->id(),
                label: $factor->id(),
                strength: $factor->strength(),
                isDefault: $factor->id() === $defaultFactorId,
            ),
            $this->registry->all(),
        ));
    }
}
```

- [ ] **Step 4: Bind it**

In `src/VouchServiceProvider.php`'s `register()`, alongside the existing bindings:

```php
        $this->app->singleton(
            \Fissible\Vouch\Flow\ScreenBuilder::class,
            fn ($app): \Fissible\Vouch\Flow\ScreenBuilder => new \Fissible\Vouch\Flow\ScreenBuilder(
                new \Fissible\Vouch\Kernel\Enumeration\ErrorShaper(),
                $app->make(\Fissible\Vouch\Factors\FactorRegistry::class),
            ),
        );
```

- [ ] **Step 5: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Flow/ScreenBuilderTest.php`
Expected: PASS, 7 tests.

If "marks exactly one offered factor as the default" fails, the registry contains a factor whose `id()` does not match any value passed as `$defaultFactorId` — fix the caller, do not relax the assertion to "at most one".

- [ ] **Step 6: Prove the disclosure boundary is load-bearing**

```bash
cp src/Flow/ScreenBuilder.php /tmp/sb2.bak
```

Two probes:

1. Make `refused()` return `$base` directly, bypassing `ErrorShaper`. The strict-posture indistinguishability test must FAIL. If it passes, the test is comparing two screens that were identical for a reason other than shaping.
2. Delete the `Locked` guard. The "refuses to shape a locked outcome" test must FAIL.

Restore after each:

```bash
cp /tmp/sb2.bak src/Flow/ScreenBuilder.php
vendor/bin/pest tests/Flow/ScreenBuilderTest.php   # green again
```

- [ ] **Step 7: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 8: Commit**

```bash
git add src/Flow/ScreenBuilder.php src/VouchServiceProvider.php tests/Flow/ScreenBuilderTest.php
git commit -m "feat: add ScreenBuilder as the sole disclosure path

Every user-visible auth error goes through the kernel's ErrorShaper under the
tenant's posture. Refuses Outcome::Locked outright: ErrorShaper discloses that
case in full under every posture, which is safe only when rate limits apply
identically to known and unknown identifiers, and 2.3 ships none -- so a Locked
screen with a null RetryPolicy would fabricate a lockout nobody measured."
```

---

## Task 4: `AuthFlow` — the orchestrator

**Files:**
- Create: `src/Flow/AuthFlow.php`
- Test: `tests/Flow/AuthFlowTest.php`

**Interfaces:**
- Consumes: `FlowRequest`, `FlowResult` variants, `AuthSuccess` (Task 2); `ScreenBuilder` (Task 3); `FactorRegistry`, `VerificationRequest`, `FactorResult` (2.2); `AttemptStore`, `TransitionOutcome` (2.1/2.2); kernel `TransitionRules`, `PolicyResolver`, `SatisfiabilityEvaluator`, `AssuranceFacts`, `AssuranceVocabulary`
- Produces: `AuthFlow::advance(FlowRequest $request): FlowResult`

**The rules this class exists to keep.** It never re-derives transition legality — it calls the store, which asks the kernel. It never writes single-use state — it passes driver mutations to `transition()`. It never touches a session, a request or a response. And it never constructs an error message; `ScreenBuilder` does.

- [ ] **Step 1: Write the failing test**

Create `tests/Flow/AuthFlowTest.php`. These tests exercise the real registry, real store and real database — the flow is the first component where a mock would hide the interactions that matter.

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const FLOW_BINDING_SOURCE = 'host-session-under-test';

function flowBinding(): string
{
    return SessionBinding::for(FLOW_BINDING_SOURCE, BindingDomain::Attempt);
}

function flow(): AuthFlow
{
    return app(AuthFlow::class);
}

function policyRequiring(array $document): void
{
    AuthPolicy::create(['tenant_id' => null, 'scope' => 'login', 'document' => $document, 'posture' => 'friendly']);
}

function enrolledPassword(int $userId = 7, string $password = 'correct horse battery staple'): void
{
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll($userId, ['password' => $password]);
}

function beginRequest(array $input = []): FlowRequest
{
    return new FlowRequest(null, 'begin', $input, flowBinding());
}

function advanceRequest(string $handle, array $input, string $binding = null): FlowRequest
{
    return new FlowRequest($handle, 'submit', $input, $binding ?? flowBinding());
}

it('begins an attempt bound to the supplied context', function (): void {
    $result = flow()->advance(beginRequest());

    expect($result)->toBeInstanceOf(Continuing::class);

    $attempt = AuthAttempt::query()->latest('id')->firstOrFail();

    expect($attempt->bound_context)->toBe(flowBinding())
        ->and($attempt->bound_context)->not->toContain(FLOW_BINDING_SOURCE);
});

it('refuses to advance an attempt from a different bound context', function (): void {
    /*
     * The handle identifies the attempt; it must not also authorize it. This is
     * the test that makes ContextMismatch a security invariant rather than a
     * conditional one.
     */
    policyRequiring(['all_of' => ['password']]);
    enrolledPassword();

    $begun = flow()->advance(beginRequest());
    $handle = AuthAttempt::query()->latest('id')->firstOrFail()->handle;

    $result = flow()->advance(advanceRequest(
        $handle,
        ['identifier' => 'ada@acme.example'],
        SessionBinding::for('a-different-host-session', BindingDomain::Attempt),
    ));

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and($result->screen->errors)->not->toBe([]);
});

it('authenticates when the policy is satisfied', function (): void {
    policyRequiring(['all_of' => ['password']]);
    enrolledPassword();

    $handle = beginAndIdentify(7);

    $result = flow()->advance(advanceRequest($handle, ['code' => 'correct horse battery staple']));

    expect($result)->toBeInstanceOf(Authenticated::class)
        ->and($result->success->userId)->toBe(7)
        ->and($result->success->amr())->toBe(['password'])
        ->and($result->success->boundContext)->toBe(flowBinding());
});

it('does not rotate any session itself', function (): void {
    // AuthFlow is not session-aware. Authenticated carries the facts;
    // SessionLifecycle performs the rotation, after this returns.
    policyRequiring(['all_of' => ['password']]);
    enrolledPassword();

    $handle = beginAndIdentify(7);
    flow()->advance(advanceRequest($handle, ['code' => 'correct horse battery staple']));

    expect(\Fissible\Vouch\Models\AuthSession::count())->toBe(0);
});

it('opens recovery grace rather than authenticating on a recovery code', function (): void {
    /*
     * Recovery evidence is filtered out of satisfiability by the kernel, so the
     * policy is never satisfied by it. The flow must recognise that and open the
     * constrained capability instead of leaving the user stuck.
     */
    policyRequiring(['all_of' => ['password']]);
    enrolledPassword();
    $codes = array_map(
        static fn ($secret): string => $secret->reveal(),
        app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(7, [])->secrets,
    );

    $handle = beginAndIdentify(7);
    $result = flow()->advance(new FlowRequest($handle, 'recover', ['code' => $codes[0]], flowBinding()));

    expect($result)->toBeInstanceOf(RecoveryGraceStarted::class)
        ->and($result->userId)->toBe(7);
});

it('burns a recovery code only through the store', function (): void {
    // The driver returns a DisableCredential mutation; the flow hands it to
    // transition(). If the flow burned it directly, a later transition failure
    // would leave the code spent and the user unauthenticated.
    policyRequiring(['all_of' => ['password']]);
    enrolledPassword();
    $codes = array_map(
        static fn ($secret): string => $secret->reveal(),
        app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(7, [])->secrets,
    );

    $handle = beginAndIdentify(7);
    flow()->advance(new FlowRequest($handle, 'recover', ['code' => $codes[0]], flowBinding()));

    expect(AuthCredential::where('type', 'recovery_code')->whereNull('disabled_at')->count())->toBe(9);
});

/** Begins an attempt and submits the identifier, returning the handle. */
function beginAndIdentify(int $userId): string
{
    \Fissible\Vouch\Models\AuthIdentifier::create([
        'user_id' => $userId, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);

    flow()->advance(beginRequest());
    $handle = AuthAttempt::query()->latest('id')->firstOrFail()->handle;
    flow()->advance(advanceRequest($handle, ['identifier' => 'ada@acme.example']));

    return $handle;
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `vendor/bin/pest tests/Flow/AuthFlowTest.php`
Expected: FAIL — `AuthFlow` not found.

- [ ] **Step 3: Write `AuthFlow`**

The orchestrator is the largest single file in this phase. Structure it as one public `advance()` plus private handlers per step, so the state machine is readable in one screen.

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Policy\PolicyParser;
use Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Psr\Clock\ClockInterface;

/**
 * Drives an authentication attempt.
 *
 * Four things this class never does, each of which has a home elsewhere:
 *
 *  - It never re-derives transition legality. It calls AttemptStore, which asks
 *    the kernel's TransitionRules. Re-deriving would be a second implementation
 *    of a rule that is already mutation-tested.
 *  - It never writes single-use state. Driver mutations go to transition() and
 *    are applied inside the transaction that advances the attempt.
 *  - It never touches a session, request or response. Nothing HTTP-shaped
 *    crosses this boundary, which is what lets one core drive both the JSON
 *    surface and Phase 3's adapters.
 *  - It never constructs an error message. ScreenBuilder does, through
 *    ErrorShaper.
 */
final readonly class AuthFlow
{
    public function __construct(
        private AttemptStore $store,
        private FactorRegistry $registry,
        private ScreenBuilder $screens,
        private SatisfiabilityEvaluator $evaluator,
        private AssuranceVocabulary $vocabulary,
        private ClockInterface $clock,
        private int $attemptTtlSeconds,
    ) {}

    public function advance(FlowRequest $request): FlowResult
    {
        if ($request->handle === null) {
            return new Continuing($this->screens->identify($this->posture(null)));
        }

        $attempt = AuthAttempt::query()->where('handle', $request->handle)->first();

        /*
         * A missing attempt and a context mismatch are the same shaped refusal.
         * Distinguishing them would tell a handle holder whether the handle is
         * real, which is an oracle over attempt handles.
         */
        if (! $attempt instanceof AuthAttempt || $attempt->bound_context !== $request->boundContext) {
            return new Continuing($this->screens->refused(
                AuthStep::Identify,
                Outcome::CredentialRejected,
                $this->posture(null),
            ));
        }

        return match ($attempt->state) {
            AttemptState::Initiated => $this->identify($attempt, $request),
            default => $this->verify($attempt, $request),
        };
    }

    private function identify(AuthAttempt $attempt, FlowRequest $request): FlowResult
    {
        $posture = $this->posture($attempt->tenant_id);
        $value = $request->string('identifier');

        if ($value === null || $value === '') {
            return new Continuing($this->screens->refused(AuthStep::Identify, Outcome::CredentialRejected, $posture));
        }

        $identifier = AuthIdentifier::query()->where('value', $value)->whereNotNull('verified_at')->first();

        /*
         * An unknown identifier still advances the attempt and still offers a
         * challenge screen. Refusing here would make the identify step itself an
         * account-existence oracle regardless of what the message says: the flow
         * would visibly stop for unknown identifiers and continue for known
         * ones. The shaped screen carries whatever posture permits.
         */
        $userId = $identifier?->user_id;

        $attempt->update(['identifier' => $value, 'user_id' => $userId]);

        if ($this->store->transition($attempt, AttemptState::Identified) !== TransitionOutcome::Succeeded) {
            return new Continuing($this->screens->refused(AuthStep::Identify, Outcome::CredentialRejected, $posture));
        }

        return new Continuing($this->screens->challenge($this->defaultFactorFor($userId), $posture));
    }

    private function verify(AuthAttempt $attempt, FlowRequest $request): FlowResult
    {
        $posture = $this->posture($attempt->tenant_id);
        $factorId = $request->action === 'recover' ? 'recovery_code' : $this->defaultFactorFor($attempt->user_id);

        if (! $this->registry->has($factorId) || $attempt->user_id === null) {
            return new Continuing($this->screens->refused(AuthStep::Challenge, Outcome::CredentialRejected, $posture, $factorId));
        }

        $result = $this->registry->get($factorId)->verify(new VerificationRequest(
            attempt: $attempt,
            input: $request->input,
            clientIp: $request->clientIp,
            clientUserAgent: $request->clientUserAgent,
        ));

        if (! $result->isSatisfied()) {
            return new Continuing($this->screens->refused(AuthStep::Challenge, Outcome::CredentialRejected, $posture, $factorId));
        }

        $satisfied = array_values([...$this->existingFactors($attempt), $result->factor]);
        $isRecovery = $result->factor->strength === FactorStrength::Recovery;
        $target = $isRecovery ? AttemptState::FactorSatisfied : $this->targetState($attempt, $satisfied);

        if ($this->store->transition($attempt, $target, ...$result->mutations) !== TransitionOutcome::Succeeded) {
            return new Continuing($this->screens->refused(AuthStep::Challenge, Outcome::CredentialRejected, $posture, $factorId));
        }

        $attempt->update(['satisfied_factors' => $this->encode($satisfied)]);

        if ($isRecovery) {
            return new RecoveryGraceStarted(
                userId: $attempt->user_id,
                boundContext: $request->boundContext,
                screen: $this->screens->challenge('password', $posture),
            );
        }

        if ($target !== AttemptState::Authenticated) {
            return new Continuing($this->screens->challenge($this->defaultFactorFor($attempt->user_id), $posture));
        }

        $facts = AssuranceFacts::fromFactors($satisfied);

        return new Authenticated(
            new AuthSuccess(
                userId: $attempt->user_id,
                factors: $satisfied,
                facts: $facts,
                acr: $this->vocabulary->name($facts),
                boundContext: $request->boundContext,
            ),
            $this->screens->challenge($this->defaultFactorFor($attempt->user_id), $posture),
        );
    }
}
```

**Note for the implementer:** the private helpers referenced above — `posture()`, `defaultFactorFor()`, `existingFactors()`, `encode()`, `targetState()` — are yours to write. `targetState()` must ask the kernel's `SatisfiabilityEvaluator` against the parsed policy and return `AttemptState::Authenticated` only when the verdict is satisfied, `AttemptState::FactorSatisfied` otherwise. `posture()` reads `AuthPolicy` for the tenant and falls back to the configured default. Do not put policy *evaluation* in any of them — call the evaluator.

- [ ] **Step 4: Bind it**

```php
        $this->app->singleton(
            \Fissible\Vouch\Flow\AuthFlow::class,
            fn ($app): \Fissible\Vouch\Flow\AuthFlow => new \Fissible\Vouch\Flow\AuthFlow(
                $app->make(\Fissible\Vouch\Contracts\AttemptStore::class),
                $app->make(\Fissible\Vouch\Factors\FactorRegistry::class),
                $app->make(\Fissible\Vouch\Flow\ScreenBuilder::class),
                new \Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator(),
                $app->make(\Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class),
                $app->make(\Psr\Clock\ClockInterface::class),
                config()->integer('vouch.attempts.ttl_seconds'),
            ),
        );
```

`AssuranceVocabulary` is an interface; bind `NistAssuranceVocabulary` to it in the same `register()` if it is not already bound.

- [ ] **Step 5: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Flow/AuthFlowTest.php`
Expected: PASS, 6 tests.

- [ ] **Step 6: Prove three properties are load-bearing**

```bash
cp src/Flow/AuthFlow.php /tmp/af.bak
```

1. Drop the `bound_context` comparison in `advance()`. The cross-context test must FAIL. **This is the most important probe in the task** — without it the handle is a bearer credential.
2. Make `verify()` disable the matched recovery credential itself before returning. The "burns a recovery code only through the store" test must still pass at 9 — if it does, the assertion is not distinguishing who burned it, and needs to assert the store did (add a failing-transition case).
3. Return `Authenticated` for a recovery result instead of `RecoveryGraceStarted`. The recovery test must FAIL. If it passes, the two paths are not actually distinguished and a stolen recovery code becomes a session.

Restore after each and re-verify green.

- [ ] **Step 7: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 8: Commit**

```bash
git add src/Flow/AuthFlow.php src/VouchServiceProvider.php tests/Flow/AuthFlowTest.php
git commit -m "feat: add the AuthFlow orchestrator

Never re-derives transition legality, never writes single-use state, never
touches a session, never constructs an error message. A missing attempt and a
context mismatch produce the same shaped refusal so a handle holder cannot
learn whether a handle is real."
```

---

## Task 5: `SessionLifecycle` — the fail-closed rotation protocol

**Files:**
- Create: `src/Sessions/SessionLifecycle.php`, `src/Sessions/SessionRotationFailed.php`
- Test: `tests/Sessions/SessionLifecycleTest.php`
- Modify: `tests/Pest.php` (add `'Sessions'`)

**Interfaces:**
- Consumes: `AuthSuccess` (Task 2); `BindingDomain`, `SessionBinding` (Task 1); `AuthSession`, `RevokedReason` (2.1)
- Produces:
  - `SessionLifecycle::establish(AuthSuccess $success): void`
  - `SessionLifecycle::revokeSiblings(int $userId, string $keepBinding, RevokedReason $reason): int`
  - `SessionRotationFailed extends RuntimeException`

**The protocol, and why the order is the mechanism.** The host session store and the database are different stores; there is no shared transaction and this class must not claim one.

1. Regenerate the host session ID.
2. Rotate or create the `auth_sessions` record for the new binding.
3. **Only then** log the user into the host guard.
4. If step 2 fails, destroy the regenerated host session and throw.

Guard login is last precisely so that every earlier failure lands on an unauthenticated session. A user must never be left guard-authenticated with no record — that session would pass the host's checks and fail vouch's per-request read forever.

- [ ] **Step 1: Write the failing test**

Create `tests/Sessions/SessionLifecycleTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function lifecycle(): SessionLifecycle
{
    return app(SessionLifecycle::class);
}

function factor(string $id = 'password'): SatisfiedFactor
{
    return new SatisfiedFactor($id, '7', FactorKind::Knowledge, FactorStrength::Knowledge,
        false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'));
}

function success(int $userId = 7, string $acr = 'aal1'): AuthSuccess
{
    return new AuthSuccess($userId, [factor()], AssuranceFacts::fromFactors([factor()]), $acr, 'ignored');
}

it('regenerates the host session and records the new binding', function (): void {
    session()->start();
    $before = session()->getId();

    lifecycle()->establish(success());

    $after = session()->getId();

    expect($after)->not->toBe($before)
        ->and(AuthSession::count())->toBe(1)
        ->and(AuthSession::firstOrFail()->session_binding)
        ->toBe(SessionBinding::for($after, BindingDomain::Session));
});

it('never stores the raw session id', function (): void {
    session()->start();
    lifecycle()->establish(success());

    expect(\Illuminate\Support\Facades\DB::table('auth_sessions')->value('session_binding'))
        ->not->toBe(session()->getId());
});

it('rotates in place rather than adding a row', function (): void {
    // 2.1 established rotate-in-place; a second row would orphan the first
    // binding and leave a session nothing can revoke.
    session()->start();
    lifecycle()->establish(success());
    lifecycle()->establish(success(acr: 'aal2'));

    expect(AuthSession::count())->toBe(1)
        ->and(AuthSession::firstOrFail()->amr)->toBe(['password']);
});

it('revokes sibling sessions without touching the current one', function (): void {
    session()->start();
    lifecycle()->establish(success());
    $keep = AuthSession::firstOrFail()->session_binding;

    AuthSession::create(['session_binding' => str_repeat('a', 64), 'user_id' => 7, 'amr' => ['password']]);
    AuthSession::create(['session_binding' => str_repeat('b', 64), 'user_id' => 8, 'amr' => ['password']]);

    $revoked = lifecycle()->revokeSiblings(7, $keep, RevokedReason::PasswordChanged);

    expect($revoked)->toBe(1)
        ->and(AuthSession::where('session_binding', $keep)->firstOrFail()->revoked_at)->toBeNull()
        ->and(AuthSession::where('session_binding', str_repeat('a', 64))->firstOrFail()->revoked_reason)
        ->toBe(RevokedReason::PasswordChanged)
        ->and(AuthSession::where('user_id', 8)->firstOrFail()->revoked_at)->toBeNull();
});
```

- [ ] **Step 2: Run it and watch it fail**

Run: `vendor/bin/pest tests/Sessions/SessionLifecycleTest.php`
Expected: FAIL — `SessionLifecycle` not found.

- [ ] **Step 3: Write `SessionRotationFailed`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use RuntimeException;
use Throwable;

/**
 * The server-side session record could not be written after the host session
 * was regenerated.
 *
 * The regenerated host session has been destroyed by the time this is thrown.
 * Authentication fails closed: the alternative is a session the host guard
 * accepts and vouch has no record of, which would pass every host check and
 * fail vouch's per-request read for as long as it lives.
 */
final class SessionRotationFailed extends RuntimeException
{
    public static function after(Throwable $previous): self
    {
        return new self(
            'Vouch could not record the rotated session. The regenerated host session has '
            . 'been destroyed and authentication refused, because a guard-authenticated '
            . 'session with no vouch record is worse than a failed login.',
            0,
            $previous,
        );
    }
}
```

- [ ] **Step 4: Write `SessionLifecycle`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Models\AuthSession;
use Illuminate\Contracts\Session\Session;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Owns §7.5: rotate on every assurance increase, record the binding, revoke
 * siblings on credential change.
 *
 * THE ORDER IS THE MECHANISM. The host session store and the database are
 * different stores; there is no shared transaction and this class does not
 * pretend otherwise. Instead the guard login happens last, so every earlier
 * failure lands on an unauthenticated session.
 */
final readonly class SessionLifecycle
{
    public function __construct(
        private Session $session,
        private ClockInterface $clock,
    ) {}

    /**
     * @throws SessionRotationFailed when the record cannot be written.
     */
    public function establish(AuthSuccess $success): void
    {
        // 1. Regenerate. §7.5 requires this on every assurance increase, not
        //    only at login: a step-up that raised assurance without rotating
        //    leaves the pre-step-up session ID valid at the higher level.
        $this->session->regenerate();

        $binding = SessionBinding::for($this->session->getId(), BindingDomain::Session);

        try {
            // 2. Rotate in place. 2.1 ships this shape with a test that the row
            //    count stays at one; a second row would orphan the old binding.
            AuthSession::query()->updateOrCreate(
                ['user_id' => $success->userId, 'revoked_at' => null],
                [
                    'session_binding' => $binding,
                    'amr' => $success->amr(),
                    'acr' => $success->acr,
                    'recovery_grace_expires_at' => null,
                ],
            );
        } catch (Throwable $failure) {
            // 4. Destroy the regenerated session and fail closed. Nothing has
            //    logged in yet, which is the entire point of the ordering.
            $this->session->invalidate();

            throw SessionRotationFailed::after($failure);
        }

        // 3. The caller logs into the host guard only after this returns.
    }

    /**
     * Revoke every other live session for this user.
     *
     * Setting revoked_at is inert on its own — the host's cookie still works.
     * ValidatesVouchSession is the authoritative read that makes it real.
     */
    public function revokeSiblings(int $userId, string $keepBinding, RevokedReason $reason): int
    {
        return AuthSession::query()
            ->where('user_id', $userId)
            ->where('session_binding', '!=', $keepBinding)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => $this->clock->now(), 'revoked_reason' => $reason]);
    }
}
```

**Implementer note:** `establish()` does not call the host guard. The result handler in Task 8 calls `Auth::loginUsingId()` *after* `establish()` returns, which is step 3. Keeping the guard call out of this class is what makes the ordering testable without a guard.

- [ ] **Step 5: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Sessions/SessionLifecycleTest.php`
Expected: PASS, 4 tests.

- [ ] **Step 6: Prove the fail-closed branch**

This branch is the one that leaves someone guard-authenticated with no record, so it needs a real test rather than only a probe. Add:

```php
it('destroys the regenerated session and fails closed when the record cannot be written', function (): void {
    session()->start();

    // Remove the table so the write throws. DatabaseMigrations, not
    // RefreshDatabase: MySQL implicitly commits on DDL and would destroy the
    // wrapping transaction's savepoint.
    \Illuminate\Support\Facades\Schema::drop('auth_sessions');

    $before = session()->getId();

    try {
        lifecycle()->establish(success());
        $this->fail('Expected SessionRotationFailed.');
    } catch (\Fissible\Vouch\Sessions\SessionRotationFailed) {
        // expected
    }

    expect(session()->getId())->not->toBe($before);
});
```

Put this test in its own file, `tests/Sessions/SessionRotationFailureTest.php`, with `uses(DatabaseMigrations::class);` — the DDL requirement is the same one that forced `EnrollmentGuardErrorsTest` into its own file in 2.2.

Then probe it: remove the `catch` block's `$this->session->invalidate()` call and confirm the test fails.

- [ ] **Step 7: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 8: Commit**

```bash
git add src/Sessions/SessionLifecycle.php src/Sessions/SessionRotationFailed.php tests/Sessions tests/Pest.php
git commit -m "feat: add the fail-closed session rotation protocol

The session store and the database share no transaction, so the ordering is the
mechanism: regenerate, record, and only then let the caller log into the host
guard. A record failure destroys the regenerated session and refuses, because a
guard-authenticated session with no vouch record passes every host check and
fails vouch's per-request read for as long as it lives."
```

---

## Task 6: `ValidatesVouchSession` — the authoritative per-request read

**Files:** Create `src/Http/Middleware/ValidatesVouchSession.php`; modify `src/VouchServiceProvider.php`; test `tests/Http/ValidatesVouchSessionTest.php`; modify `tests/Pest.php` (add `'Http'`).

**Interfaces:**
- Consumes: `SessionBinding`, `BindingDomain` (Task 1); `AuthSession`, `RevokedReason` (2.1)
- Produces: middleware alias `vouch.session`; boot-time assertion that it is present in the `web` group

Revocation without an authoritative read is only a database annotation — the host's cookie still works. This middleware is what makes `revokeSiblings()` real.

- [ ] **Step 1: Write the failing test**

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Route::middleware(['web', 'vouch.session'])->get('/probe', fn (): string => 'reached');
});

it('lets a request with no vouch record through untouched', function (): void {
    // Vouch does not own every session. A request it has no record of is not
    // vouch's business, and blocking it would break the host's own auth.
    $this->get('/probe')->assertOk()->assertSee('reached');
});

it('lets a live session through', function (): void {
    $this->startSession();
    AuthSession::create([
        'session_binding' => SessionBinding::for(session()->getId(), BindingDomain::Session),
        'user_id' => 7, 'amr' => ['password'],
    ]);

    $this->get('/probe')->assertOk();
});

it('refuses a revoked session and destroys it', function (): void {
    $this->startSession();
    $id = session()->getId();
    AuthSession::create([
        'session_binding' => SessionBinding::for($id, BindingDomain::Session),
        'user_id' => 7, 'amr' => ['password'],
        'revoked_at' => now(), 'revoked_reason' => RevokedReason::PasswordChanged,
    ]);

    $this->get('/probe')->assertRedirect();
    expect(session()->getId())->not->toBe($id);
});
```

- [ ] **Step 2: Run it and watch it fail.** `vendor/bin/pest tests/Http/ValidatesVouchSessionTest.php` — FAIL, alias not registered.

- [ ] **Step 3: Write the middleware**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http\Middleware;

use Closure;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Resolves the request's session against auth_sessions on every request.
 *
 * Setting revoked_at changes nothing on its own — the host's cookie still
 * works. This read is what makes "all other sessions invalidated on password
 * change" a mechanism rather than a documented promise. One indexed lookup per
 * request is the correct price for that.
 *
 * A request with no vouch record passes through untouched: vouch does not own
 * every session, and refusing what it has no record of would break the host's
 * own authentication.
 *
 * Grace-bound sessions are handled by GraceGuard on vouch's own grace routes,
 * not here. They are never authenticated in the first place, so there is
 * nothing for this middleware to refuse.
 */
final class ValidatesVouchSession
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! $request->hasSession()) {
            return $next($request);
        }

        $record = AuthSession::query()
            ->where('session_binding', SessionBinding::for($request->session()->getId(), BindingDomain::Session))
            ->first();

        if (! $record instanceof AuthSession) {
            return $next($request);
        }

        if ($record->revoked_at !== null) {
            $request->session()->invalidate();

            return redirect()->to('/');
        }

        return $next($request);
    }
}
```

- [ ] **Step 4: Register it and fail boot if absent**

In `boot()`:

```php
        $router = $this->app->make(\Illuminate\Routing\Router::class);
        $router->aliasMiddleware('vouch.session', ValidatesVouchSession::class);
        $router->pushMiddlewareToGroup('web', ValidatesVouchSession::class);

        /*
         * A runtime check is authoritative only on requests that actually
         * traverse it. Vouch controls its own code path, but not the host's
         * routes -- so the middleware's PRESENCE is asserted at boot, and its
         * absence is a hard failure rather than a silently unguarded app.
         */
        if (! in_array(ValidatesVouchSession::class, $router->getMiddlewareGroups()['web'] ?? [], true)) {
            throw new \RuntimeException(
                'Vouch requires ValidatesVouchSession in the "web" middleware group. Without '
                . 'it, revoking a session sets a column nobody reads and the revoked session '
                . 'keeps working.',
            );
        }
```

- [ ] **Step 5: Run the tests.** Expected PASS, 3 tests.

- [ ] **Step 6: Probe.** `cp` the middleware aside; make `handle()` always `return $next($request);`. The revoked-session test must FAIL. Restore and re-verify. Then remove the `pushMiddlewareToGroup` line and confirm the boot assertion throws.

- [ ] **Step 7:** `composer test && composer stan` — both green.

- [ ] **Step 8: Commit**

```bash
git add src/Http/Middleware/ValidatesVouchSession.php src/VouchServiceProvider.php tests/Http tests/Pest.php
git commit -m "feat: make session revocation authoritative with a per-request read

Revocation without an authoritative read is only a database annotation. The
middleware is pushed to the web group and its absence fails boot, because a
runtime check is authoritative only on requests that traverse it."
```

---

## Task 7: `GraceGuard` and the grace routes

**Files:** Create `src/Recovery/GraceGuard.php`, `src/Recovery/GraceController.php`; test `tests/Http/GraceRoutesTest.php`.

**Interfaces:**
- Consumes: `SessionBinding`/`BindingDomain` (Task 1); `AuthSession`, `RevokedReason` (2.1); `FactorRegistry` (2.2); `SessionLifecycle` (Task 5)
- Produces: `GraceGuard::activeFor(string $hostSessionId): ?AuthSession`; `GraceGuard::expireIfLapsed(string $hostSessionId): void`

**Everything here is decided in database time.** Never load a row and compare `recovery_grace_expires_at` to PHP's `now()` — that recreates the app/database clock seam that silently invalidated 2.2's TOTP tests.

- [ ] **Step 1: Write the failing test**

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;

uses(RefreshDatabase::class);

function graceRow(string $hostSessionId, ?Carbon $expires = null, array $extra = []): AuthSession
{
    return AuthSession::create(array_merge([
        'session_binding' => SessionBinding::for($hostSessionId, BindingDomain::Session),
        'user_id' => 7,
        'amr' => ['recovery_code'],
        'recovery_grace_expires_at' => $expires ?? now()->addMinutes(15),
    ], $extra));
}

it('resolves an active grace record', function (): void {
    graceRow('host-1');

    expect(app(GraceGuard::class)->activeFor('host-1'))->toBeInstanceOf(AuthSession::class);
});

it('does not resolve an expired one', function (): void {
    graceRow('host-1', now()->subMinute());

    expect(app(GraceGuard::class)->activeFor('host-1'))->toBeNull();
});

it('decides expiry by the database clock, not the application clock', function (): void {
    /*
     * The control that matters. Without it the predicate could be rewritten as
     * a PHP comparison and every other grace test would stay green -- exactly
     * how 2.2's TOTP tests passed while real time sat before a frozen expiry.
     */
    graceRow('host-1', now()->addMinutes(15));

    // Move the application clock far past the deadline. The database clock has
    // not moved, so the row is still live.
    Carbon::setTestNow(now()->addHours(2));

    expect(app(GraceGuard::class)->activeFor('host-1'))->toBeInstanceOf(AuthSession::class);
});

it('marks a lapsed row grace_expired', function (): void {
    graceRow('host-1', now()->subMinute());

    app(GraceGuard::class)->expireIfLapsed('host-1');

    expect(AuthSession::firstOrFail()->revoked_reason)->toBe(RevokedReason::GraceExpired);
});

it('never overwrites an existing revocation reason', function (): void {
    /*
     * Audit integrity. The session is destroyed and grace routes refuse either
     * way, so the recorded cause is the ONLY thing distinguishing a deliberate
     * revocation from an ordinary lapse -- and only this test protects it.
     * Without the guard the system files a false audit entry about itself.
     */
    graceRow('host-1', now()->subMinute(), [
        'revoked_at' => now()->subMinutes(5),
        'revoked_reason' => RevokedReason::AdminRevoked,
    ]);

    app(GraceGuard::class)->expireIfLapsed('host-1');

    expect(AuthSession::firstOrFail()->revoked_reason)->toBe(RevokedReason::AdminRevoked);
});
```

- [ ] **Step 2: Run it and watch it fail.**

- [ ] **Step 3: Write `GraceGuard`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Expression;

/**
 * Resolves the recovery-grace capability, entirely in database time.
 *
 * NEVER load a row and compare recovery_grace_expires_at to PHP's now(). That
 * recreates the application/database clock seam documented on
 * DatabaseAttemptStore::now() -- the one that silently invalidated Phase 2.2's
 * TOTP tests, which were green only while real time happened to sit before a
 * frozen expiry.
 */
final readonly class GraceGuard
{
    public function __construct(private ConnectionInterface $connection) {}

    /** The live grace record for this host session, or null. */
    public function activeFor(string $hostSessionId): ?AuthSession
    {
        return AuthSession::query()
            ->where('session_binding', SessionBinding::for($hostSessionId, BindingDomain::Session))
            ->whereNotNull('recovery_grace_expires_at')
            ->whereNull('revoked_at')
            // The predicate, not a PHP comparison.
            ->where('recovery_grace_expires_at', '>', $this->now())
            ->first();
    }

    /**
     * Mark a lapsed grace row expired — without overwriting a prior reason.
     *
     * The `revoked_at IS NULL` guard is the same shape as 2.2's
     * DisableCredential predicate. If the row was already admin_revoked, the
     * update affects no rows and the existing reason stands. The session is
     * destroyed and grace routes refuse either way; only the audit record
     * differs, and a false entry there is produced by the system itself rather
     * than by an attacker.
     */
    public function expireIfLapsed(string $hostSessionId): void
    {
        $this->connection->table('auth_sessions')
            ->where('session_binding', SessionBinding::for($hostSessionId, BindingDomain::Session))
            ->whereNotNull('recovery_grace_expires_at')
            ->whereNull('revoked_at')
            ->where('recovery_grace_expires_at', '<=', $this->now())
            ->update(['revoked_at' => $this->now(), 'revoked_reason' => RevokedReason::GraceExpired->value]);
    }

    /** @return Expression<'CURRENT_TIMESTAMP'> */
    private function now(): Expression
    {
        return new Expression('CURRENT_TIMESTAMP');
    }
}
```

- [ ] **Step 4: Write `GraceController`**

Two actions. **Enrollment** resolves the grace record via `activeFor()`, enrolls the requested factor through the registry, and returns a `ScreenSpec`. **Completion** re-resolves `activeFor()` **at the mutation boundary**, requires fresh non-recovery satisfied-factor evidence from the current attempt, then runs `SessionLifecycle::establish()` and only afterwards logs into the host guard.

The re-check is not optional: a row live when the request arrived can lapse before the mutation lands, and completion is the mutation that hands over an authenticated session.

- [ ] **Step 5: Run the tests.** Expected PASS, 5 tests.

- [ ] **Step 6: Probes**

1. Replace `activeFor()`'s database predicate with a PHP comparison against the loaded row. The database-clock test must FAIL.
2. Remove `whereNull('revoked_at')` from `expireIfLapsed()`. The audit-integrity test must FAIL.
3. Move completion's `activeFor()` re-check to request entry only. Add a test that expires the row between entry and mutation and confirm it fails without the re-check.

- [ ] **Step 7:** `composer test && composer stan`.

- [ ] **Step 8: Commit**

```bash
git add src/Recovery tests/Http/GraceRoutesTest.php
git commit -m "feat: add the recovery-grace guard, decided in database time

Expiry lives in the query predicate, never a PHP comparison -- the seam that
silently invalidated 2.2's TOTP tests. grace_expired is written only under a
revoked_at IS NULL guard so a prior admin_revoked survives; the session dies
either way, so the audit record is the only thing that distinguishes them."
```

---

## Task 8: The HTTP surface

**Files:** Create `routes/vouch.php`, `src/Http/AuthController.php`, `src/Http/FlowResultSerializer.php`, `src/Http/FlowResultHandler.php`; modify `src/VouchServiceProvider.php`, `config/vouch.php`; test `tests/Http/AuthEndpointTest.php`.

**Interfaces:**
- Consumes: `AuthFlow` (Task 4), `FlowResult` variants (Task 2), `SessionLifecycle` (Task 5)
- Produces: `POST {prefix}/auth` named `vouch.auth`; `FlowResultHandler::handle(FlowResult $result): FlowResult`; `FlowResultSerializer::toArray(FlowResult $result): array`

**The single-status rule.** Every well-formed authentication outcome returns **200** — unknown identifier, bad factor input, expired or consumed challenge, invalid handle, illegal advance, policy refusal. Status derives from the shaped outcome, never the underlying cause; otherwise strict posture is defeated by `curl -i` regardless of body filtering. Transport failures keep their semantics: 400 malformed JSON/schema, 419 CSRF, 405 method.

- [ ] **Step 1: Write the failing test**

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    AuthPolicy::create(['tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password']], 'posture' => 'strict']);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'a-real-password']);
    AuthIdentifier::create(['user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now()]);
});

it('begins an attempt and returns a screen', function (): void {
    $this->postJson('/vouch/auth', [])
        ->assertOk()
        ->assertJsonPath('result', 'continuing')
        ->assertJsonPath('screen.step', 'identify');
});

it('returns 200 for an unknown identifier, exactly as for a known one', function (): void {
    /*
     * The enumeration boundary at the transport layer. If these differed by
     * status, strict posture would be defeated by `curl -i` no matter how
     * carefully the body was filtered.
     */
    $handle = $this->postJson('/vouch/auth', [])->json('handle');

    $known = $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['identifier' => 'ada@acme.example']]);
    $handle2 = $this->postJson('/vouch/auth', [])->json('handle');
    $unknown = $this->postJson('/vouch/auth', ['handle' => $handle2, 'input' => ['identifier' => 'nobody@acme.example']]);

    expect($known->status())->toBe(200)->and($unknown->status())->toBe(200);
});

it('returns 200 for an invalid handle', function (): void {
    $this->postJson('/vouch/auth', ['handle' => 'not-a-real-handle', 'input' => []])->assertOk();
});

it('returns 200 for a rejected credential', function (): void {
    $handle = $this->postJson('/vouch/auth', [])->json('handle');
    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['identifier' => 'ada@acme.example']]);

    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['code' => 'wrong']])
        ->assertOk()
        ->assertJsonPath('result', 'continuing');
});

it('keeps transport semantics for a malformed body', function (): void {
    // 400 reveals request validity, not account state.
    $this->call('POST', '/vouch/auth', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{not json')
        ->assertStatus(400);
});

it('never returns the raw session id or a retry policy', function (): void {
    $response = $this->postJson('/vouch/auth', []);

    expect($response->json('screen.retry'))->toBeNull()
        ->and(json_encode($response->json()))->not->toContain(session()->getId());
});

it('logs the user in only after the session record exists', function (): void {
    $handle = $this->postJson('/vouch/auth', [])->json('handle');
    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['identifier' => 'ada@acme.example']]);

    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['code' => 'a-real-password']])
        ->assertOk()
        ->assertJsonPath('result', 'authenticated');

    expect(\Fissible\Vouch\Models\AuthSession::count())->toBe(1);
});
```

- [ ] **Step 2: Run it and watch it fail.**

- [ ] **Step 3: Write `FlowResultHandler`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http;

use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowResult;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Flow\UnknownFlowResult;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Illuminate\Contracts\Auth\Guard;

/**
 * Routes a FlowResult to its side effect, then hands it back for serialization.
 *
 * This is the seam that keeps AuthFlow HTTP-free while giving session rotation
 * an explicit completion point. It is also the only place that logs into the
 * host guard, and it does so AFTER SessionLifecycle::establish() returns —
 * step 3 of the fail-closed protocol.
 *
 * An unhandled variant throws. Falling through would silently skip session
 * rotation on a successful authentication, leaving a user who appears logged in
 * with no record.
 */
final readonly class FlowResultHandler
{
    public function __construct(
        private SessionLifecycle $lifecycle,
        private Guard $guard,
    ) {}

    public function handle(FlowResult $result): FlowResult
    {
        return match (true) {
            $result instanceof Continuing => $result,

            $result instanceof Authenticated => $this->establish($result),

            /*
             * Grace deliberately does nothing here. The host guard is never
             * invoked, and the anonymous session is retained as the bound
             * context — that is what makes a stolen recovery code a constrained
             * capability rather than an application session.
             */
            $result instanceof RecoveryGraceStarted => $result,

            default => throw UnknownFlowResult::for($result),
        };
    }

    private function establish(Authenticated $result): Authenticated
    {
        $this->lifecycle->establish($result->success);

        // Step 3, and only now: the record exists.
        $this->guard->loginUsingId($result->success->userId);

        return $result;
    }
}
```

- [ ] **Step 4: Write `FlowResultSerializer` and `AuthController`**

The serializer produces `{result: 'continuing'|'authenticated'|'recovery_grace', handle?: string, screen: {...}}`. `ScreenSpec` becomes a plain array: `step` as the enum value, `offeredFactors` and `fields` as arrays of scalars, `challengePayload` verbatim, `errors` as-is, `retry` as `null` in 2.3. It throws `UnknownFlowResult` on an unrecognised variant, matching the handler.

`AuthController` has one `__invoke`: build a `FlowRequest` (deriving `boundContext` via `SessionBinding::for($request->session()->getId(), BindingDomain::Attempt)`), call `AuthFlow::advance()`, pass the result through `FlowResultHandler`, serialize, return 200. **No `match` on `AuthStep` anywhere in it.**

- [ ] **Step 5: Write `routes/vouch.php` and register it**

```php
Route::prefix(config()->string('vouch.routes.prefix'))
    ->middleware(config()->array('vouch.routes.middleware'))
    ->group(function (): void {
        Route::post('/auth', AuthController::class)->name('vouch.auth');
        Route::post('/recovery/enroll', [GraceController::class, 'enroll'])->name('vouch.recovery.enroll');
        Route::post('/recovery/complete', [GraceController::class, 'complete'])->name('vouch.recovery.complete');
    });
```

Add to `config/vouch.php`:

```php
    'routes' => [
        'prefix' => env('VOUCH_ROUTE_PREFIX', 'vouch'),
        /*
         * Inside `web` by default so session and CSRF protection apply. This is
         * a convenience default, NOT the guarantee — AuthFlow independently
         * requires a bound context on creation and every advance, because
         * middleware configuration can change after boot.
         */
        'middleware' => ['web'],
    ],
```

- [ ] **Step 6: Run the tests.** Expected PASS, 7 tests.

- [ ] **Step 7: Probes**

1. Make the controller return 422 when the screen carries errors. The unknown/known status test must FAIL.
2. Remove the `default => throw UnknownFlowResult::for($result)` arm from the handler and replace it with `default => $result`. Add a rogue-variant test and confirm it fails — a silently unhandled variant means no session rotation on success.
3. Swap the order in `establish()` so `loginUsingId()` runs before `$this->lifecycle->establish()`. Nothing in the happy path will fail, which is the point: note in the report that ordering is protected by Task 5's fail-closed test rather than by anything here.

- [ ] **Step 8:** `composer test && composer stan`.

- [ ] **Step 9: Commit**

```bash
git add routes src/Http config/vouch.php src/VouchServiceProvider.php tests/Http/AuthEndpointTest.php
git commit -m "feat: add the single-endpoint HTTP surface

One POST /vouch/auth begins and advances; the client never names the next step.
Every well-formed outcome returns 200 so status codes cannot defeat strict
posture, while malformed bodies keep transport semantics. The host guard is
logged into only after the session record exists."
```

---

## Task 9: Ban every lockout path from 2.3

**Files:** Create `tests/Arch/LockoutBoundaryTest.php`; test `tests/Http/StrictPostureRetryTest.php`.

**Interfaces:** Consumes the 2.3 source namespaces produced by Tasks 3–8.

`ErrorShaper`'s lockout carve-out discloses the message **and** the `RetryPolicy` under every posture including strict. Its own docblock states the precondition: that is safe only if rate limits apply identically to known and unknown identifiers, including the length of the window. 2.3 ships no rate limiting, so no 2.3 path may reach it — otherwise a known identifier returns a populated retry state and an unknown one returns the uniform message with `retry: null`, which is a complete account-existence oracle obtained *under strict posture* with every kernel test green.

Task 3 guarded `ScreenBuilder`. This task makes it structural across the phase.

- [ ] **Step 1: Write the architecture scan**

```php
<?php

declare(strict_types=1);

/*
 * 2.3 owns these namespaces. The kernel is deliberately excluded: ErrorShaper
 * and AttemptState legitimately define the lockout vocabulary; what is banned
 * is 2.3 REACHING it.
 */
function lockoutScannedFiles(): array
{
    $roots = ['src/Flow', 'src/Http', 'src/Sessions', 'src/Recovery'];
    $files = [];

    foreach ($roots as $root) {
        $path = __DIR__ . '/../../' . $root;

        if (! is_dir($path)) {
            continue;
        }

        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path)) as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
    }

    return $files;
}

it('never reaches a lockout path from 2.3-owned source', function (): void {
    $banned = [
        'Outcome::Locked' => '/\bOutcome\s*::\s*Locked\b/',
        'AttemptState::Locked' => '/\bAttemptState\s*::\s*Locked\b/',
        'new RetryPolicy' => '/\bnew\s+\\\\?RetryPolicy\s*\(/',
    ];

    $offenders = [];

    foreach (lockoutScannedFiles() as $file) {
        $source = (string) file_get_contents($file);

        foreach ($banned as $label => $pattern) {
            /*
             * ScreenBuilder's guard names Outcome::Locked to refuse it. That is
             * the one legitimate mention, and it is a comparison rather than a
             * construction -- so it is excluded by name rather than by
             * loosening the pattern for everyone.
             */
            if (str_ends_with($file, 'ScreenBuilder.php') && $label === 'Outcome::Locked') {
                continue;
            }

            if (preg_match($pattern, $source) === 1) {
                $offenders[] = basename($file) . ' :: ' . $label;
            }
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});
```

- [ ] **Step 2: Write the route-level strict-posture test**

```php
it('returns retry: null for known and unknown identifiers alike, under strict posture', function (): void {
    // The scan proves no lockout is constructed. This proves none reaches the
    // wire, which is the property an attacker actually probes.
    foreach (['ada@acme.example', 'nobody@acme.example'] as $identifier) {
        $handle = $this->postJson('/vouch/auth', [])->json('handle');
        $response = $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['identifier' => $identifier]]);

        expect($response->status())->toBe(200)
            ->and($response->json('screen.retry'))->toBeNull();
    }
});

it('keeps retry null through a rejected credential too', function (): void {
    $handle = $this->postJson('/vouch/auth', [])->json('handle');
    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['identifier' => 'ada@acme.example']]);

    expect($this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['code' => 'wrong']])->json('screen.retry'))
        ->toBeNull();
});
```

Put these in `tests/Http/StrictPostureRetryTest.php` with the same strict-posture `beforeEach` as Task 8's file.

- [ ] **Step 3: Run both.** Expected PASS.

- [ ] **Step 4: Demonstrate the scan fails on a deliberate violation**

This step is the whole value of the task. Add a real lockout branch to `src/Flow/AuthFlow.php` — for example, returning `new Continuing($this->screens->refused(AuthStep::Challenge, Outcome::Locked, $posture))` on a failed verification, plus the import.

Run: `vendor/bin/pest tests/Arch/LockoutBoundaryTest.php`
Expected: **FAIL**, naming `AuthFlow.php :: Outcome::Locked`.

Then add a `new RetryPolicy(3, null)` somewhere in `src/Http/` and confirm the scan reports that too. If either passes, the scan is not covering the namespace and must be fixed before proceeding.

```bash
cp src/Flow/AuthFlow.php /tmp/af2.bak   # before editing
cp /tmp/af2.bak src/Flow/AuthFlow.php   # after
```

Record in the report exactly which offender strings the scan printed.

- [ ] **Step 5:** `composer test && composer stan`.

- [ ] **Step 6: Commit**

```bash
git add tests/Arch/LockoutBoundaryTest.php tests/Http/StrictPostureRetryTest.php
git commit -m "test: ban every lockout path from 2.3-owned source

ErrorShaper discloses lockouts unconditionally under strict posture, safe only
once 2.3b applies identical limits to existing and nonexistent identifiers.
Until then a known identifier would return a populated retry state and an
unknown one the uniform message with retry: null -- an account-existence oracle
with every kernel test green. The scan bans construction; the route tests prove
none reaches the wire."
```

---

## Task 10: Strict-posture timing equalization

**Files:** Create `src/Flow/VerificationEqualizer.php`; modify `src/Flow/AuthFlow.php`; test `tests/Flow/TimingEqualizationTest.php`.

**Interfaces:** Produces `VerificationEqualizer::equalize(EnumerationPosture $posture): void`

The single-200 rule closes the status channel. It does **not** close the timing channel: under strict posture an unknown identifier returns as fast as the lookup while a known one costs a full verify, and that difference reconstructs the account-existence oracle strict posture exists to deny. Careful body filtering and a uniform status are both defeated by a stopwatch.

**This equalizes the credential-verification branch. It does not promise end-to-end constant time**, and the docblock must say so.

- [ ] **Step 1: Write the failing test**

Test the **work performed**, not the clock. A duration assertion would be flaky in CI and would pass or fail for reasons unrelated to the control.

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;

uses(RefreshDatabase::class);

/** Counts check() calls without changing what they return. */
final class CountingHasher implements Hasher
{
    public int $checks = 0;

    public function __construct(private Hasher $inner) {}

    public function info($hashedValue): array { return $this->inner->info($hashedValue); }
    public function make($value, array $options = []): string { return $this->inner->make($value, $options); }
    public function needsRehash($hashedValue, array $options = []): bool { return $this->inner->needsRehash($hashedValue, $options); }

    public function check($value, $hashedValue, array $options = []): bool
    {
        $this->checks++;

        return $this->inner->check($value, $hashedValue, $options);
    }
}

beforeEach(function (): void {
    $this->hasher = new CountingHasher(Hash::driver());
    app()->instance('hash', $this->hasher);
    app()->instance(Hasher::class, $this->hasher);

    AuthPolicy::create(['tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password']], 'posture' => 'strict']);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'a-real-password']);
    AuthIdentifier::create(['user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now()]);
    $this->hasher->checks = 0;
});

it('performs exactly one verification for a known identifier with a wrong password', function (): void {
    $handle = $this->postJson('/vouch/auth', [])->json('handle');
    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['identifier' => 'ada@acme.example']]);
    $this->hasher->checks = 0;

    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['code' => 'wrong']]);

    expect($this->hasher->checks)->toBe(1);
});

it('performs exactly one verification for an unknown identifier too', function (): void {
    /*
     * The control. Without the dummy verify this is 0, and the difference is
     * measurable over a handful of requests -- reconstructing exactly the
     * account-existence oracle strict posture exists to deny.
     */
    $handle = $this->postJson('/vouch/auth', [])->json('handle');
    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['identifier' => 'nobody@acme.example']]);
    $this->hasher->checks = 0;

    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['code' => 'wrong']]);

    expect($this->hasher->checks)->toBe(1);
});

it('uses the active hasher for the dummy digest', function (): void {
    /*
     * A hard-coded bcrypt digest checked by an Argon-configured hasher is
     * rejected immediately, so the mitigation would return FASTER than the real
     * path and silently invert the leak it was added to close.
     */
    config(['hashing.driver' => 'argon2id']);

    $handle = $this->postJson('/vouch/auth', [])->json('handle');
    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['identifier' => 'nobody@acme.example']]);
    $this->hasher->checks = 0;

    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['code' => 'wrong']]);

    expect($this->hasher->checks)->toBe(1);
});

it('does not equalize under friendly posture', function (): void {
    // Proves the strict assertions are measuring posture rather than a
    // component that always burns a hash.
    AuthPolicy::query()->update(['posture' => 'friendly']);

    $handle = $this->postJson('/vouch/auth', [])->json('handle');
    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['identifier' => 'nobody@acme.example']]);
    $this->hasher->checks = 0;

    $this->postJson('/vouch/auth', ['handle' => $handle, 'input' => ['code' => 'wrong']]);

    expect($this->hasher->checks)->toBe(0);
});
```

- [ ] **Step 2: Run it and watch it fail.** The unknown-identifier test reports 0.

- [ ] **Step 3: Write `VerificationEqualizer`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Illuminate\Contracts\Hashing\Hasher;

/**
 * Equalizes the credential-verification branch under strict posture.
 *
 * A uniform HTTP status closes the status channel; it does not close the timing
 * one. An unknown identifier that skips the verify returns measurably faster
 * than a known one that performs it, and that difference reconstructs the
 * account-existence oracle strict posture exists to deny.
 *
 * BOUNDARY, stated honestly: this equalizes the credential-verification branch.
 * It does not promise end-to-end constant time, and full constant-time
 * guarantees across the whole flow are neither achievable nor worth pretending
 * to.
 */
final class VerificationEqualizer
{
    private ?string $dummy = null;

    public function __construct(private readonly Hasher $hasher) {}

    public function equalize(EnumerationPosture $posture): void
    {
        if ($posture !== EnumerationPosture::Strict) {
            return;
        }

        /*
         * The digest comes from the ACTIVE hasher, never a hard-coded bcrypt
         * string. An Argon-configured hasher rejects a bcrypt digest
         * immediately, which would make this branch return faster than the real
         * one and invert the very leak it closes.
         */
        $this->dummy ??= $this->hasher->make('vouch-timing-equalization-placeholder');

        $this->hasher->check('vouch-timing-equalization-placeholder', $this->dummy);
    }
}
```

- [ ] **Step 4: Call it from `AuthFlow`.** In `verify()`, when the attempt has no `user_id` or the registry finds no usable credential, call `$this->equalizer->equalize($posture)` before returning the refusal. Add the constructor dependency and the binding.

- [ ] **Step 5: Run the tests.** Expected PASS, 4 tests.

- [ ] **Step 6: Probes.** Remove the `equalize()` call — the unknown-identifier test must FAIL at 0. Replace the dummy with a hard-coded bcrypt string and run the Argon test — it must FAIL. Restore both.

- [ ] **Step 7:** `composer test && composer stan`.

- [ ] **Step 8: Commit**

```bash
git add src/Flow/VerificationEqualizer.php src/Flow/AuthFlow.php src/VouchServiceProvider.php tests/Flow/TimingEqualizationTest.php
git commit -m "feat: equalize the credential-verification branch under strict posture

A uniform status closes the status channel, not the timing one. Tested by
invocation count rather than wall clock -- a duration assertion would be flaky
and would pass or fail for reasons unrelated to the control. The dummy digest
comes from the active hasher: a hard-coded bcrypt digest under an Argon
configuration is rejected instantly and would invert the leak."
```

---

## Task 11: Interactive `RequireAssurance` and step-up

**Files:** Create `src/Http/Middleware/RequireAssurance.php`, `src/Http/AssuranceComparator.php`, `src/Vouch.php`; test `tests/Http/RequireAssuranceTest.php`.

**Interfaces:** Produces middleware alias `vouch.assurance:{level}`; `AssuranceComparator::isSufficient(AuthSession $session, string $required): bool`; `Vouch::stepUp(string $level): RedirectResponse`

**The comparison lives in `AssuranceComparator`, not in the middleware's redirect branch.** §6.3 specifies one policy object with two renderings; 2.4 adds the RFC 9470 response. Building the comparison inside the redirect branch guarantees a restructure then, so it is extracted now, before there is a second consumer to break.

**Step-up reuses `POST /vouch/auth`** with a step-up intent: policy resolves for step-up rather than login, and there is no identify step since the session already names the user. One flow cannot drift from itself.

- [ ] **Step 1: Write the failing test**

```php
it('lets a sufficient session through', function (): void { /* aal2 session, aal2 route */ });

it('redirects an insufficient session to step-up and remembers the destination', function (): void {
    // Interactive mode. The RFC 9470 rendering is 2.4's.
});

it('rotates the session when step-up raises assurance', function (): void {
    /*
     * §7.5 requires regeneration on every assurance INCREASE, not only at
     * login. A step-up that raised assurance without rotating would leave the
     * pre-step-up session ID valid at the higher level.
     */
});

it('never sees a grace session', function (): void {
    // Grace is never authenticated, so the host's own auth middleware denies a
    // protected route first. RequireAssurance is not grace's containment and
    // must not be relied on as it.
});

it('compares through AssuranceComparator rather than string equality', function (): void {
    // aal2 must satisfy a route requiring aal1. String equality would refuse a
    // stronger session, which is a lockout that looks like a security win.
});
```

Write these out fully against the fixtures established in Task 8's file.

- [ ] **Step 2: Run and watch fail. Step 3: implement. Step 4: run and pass.**

- [ ] **Step 5: Probes.** Make `isSufficient()` use `===` on the acr strings — the stronger-session test must FAIL. Remove the rotation on assurance increase — that test must FAIL.

- [ ] **Step 6:** `composer test && composer stan`. **Step 7:** commit.

---

## Task 12: The test-only reference renderer

**Files:** Create `tests/Support/ReferenceRenderer/` (a Blade view set plus a small renderer class); test `tests/Http/ReferenceRendererTest.php`.

**Interfaces:** Consumes the JSON envelope from Task 8.

An independent consumer of `ScreenSpec`, driven **through the real routes**. Asserting JSON shape alone tests the serializer against itself — the shape that produced this project's vacuous controls. This makes the contract earn its stability before Phase 3, when the second adapter would otherwise be the first thing to reveal what the first baked in wrongly.

**It is not published, not routeable, and not container-registered in production.**

- [ ] **Step 1:** Write a renderer that takes the decoded envelope and renders a Blade template per `AuthStep`, escaping every value.

- [ ] **Step 2:** Drive **every screen** — identify, challenge, enroll, recover, step_up — through the real endpoint and render each.

- [ ] **Step 3:** Drive **every error** the flow can produce under both postures.

- [ ] **Step 4: Escaping.** Submit an identifier containing `<script>alert(1)</script>` and assert the rendered output contains the escaped form and not the raw tag. §7.1.1's posture-filtered errors must survive rendering without becoming an injection surface.

- [ ] **Step 5:** Add an arch assertion that no file under `src/` references the reference-renderer namespace, and that the service provider does not register it.

- [ ] **Step 6:** `composer test && composer stan`. **Step 7:** commit.

---

## Task 13: Establish the mutation gate

**Files:** Modify `composer.json`, `PROJECT.md`.

This is the phase's stated quality bar and a **completion gate**: 2.3 is not complete until the gate is committed and green.

- [ ] **Step 1: Fix the scope and exclusion list in config BEFORE the first run.**

Add to `composer.json` two scripts covering `Fissible\Vouch` **excluding** `Fissible\Vouch\Kernel`, one full pass and one covered pass. Write the exclusion list now and do not narrow it afterwards. This is the anti-gaming constraint: narrowing after seeing the score turns a floor into a rationalization.

- [ ] **Step 2: Run both passes and capture the reports.** Do not set any `--min` yet.

- [ ] **Step 3: Audit every initial survivor.** Every one. A survivor is either a real gap to close or a documented equivalent mutant; "probably fine" is not a category.

- [ ] **Step 4: Close what the audit says to close**, then re-run both passes.

- [ ] **Step 5: Set each floor to a conservative whole number at or below the audited baseline**, and add `--min` to both scripts.

- [ ] **Step 6: Commit the commands, reports, survivor counts, baseline and floors together in `PROJECT.md`**, in the shape the cross-engine verification record uses. Include the exclusion list verbatim.

Record explicitly: **any later reduction of either floor is a security decision requiring review, never implementation convenience.**

- [ ] **Step 7:** Both passes green at their floors. **Step 8:** commit.

---

## Task 14: Cross-engine matrix and completion

**Files:** Modify `.github/workflows/ci.yml`, `PROJECT.md`.

Same completion gate as 2.2. Every leg is the **full** suite.

- [ ] **Step 1: Start containers** (`mysql:8`, `postgres:16`), waiting for readiness — and then wait a few seconds more. `mysqladmin ping` reports ready before the server accepts connections; that cost a spurious 185-failure run in 2.2.

- [ ] **Step 2: Run the full suite on MySQL, Postgres and file-backed SQLite.**

Environment variables go on as a **prefix**, never `env $VAR` — zsh does not word-split unquoted variables, and that mistake has cost a full matrix run twice in this project.

- [ ] **Step 3: Verify the grace-expiry decision from the preflight** behaves identically on all three engines, whichever resolution was chosen.

- [ ] **Step 4: Add `tests/Flow`, `tests/Sessions` and `tests/Http` to the `database-matrix` job's path list.**

- [ ] **Step 5: Record the verification in `PROJECT.md`** — exact commands, resolved engine versions, results, and the preflight decision with its reasoning.

- [ ] **Step 6: Final local gate:** `composer test && composer stan` plus all four mutation passes at their floors.

- [ ] **Step 7: Confirm the kernel boundary held:** `git diff --stat main -- src/Kernel` must be empty. The arch scans are a denylist, not a proof.

- [ ] **Step 8: Commit. Step 9: Finish the branch** using `superpowers:finishing-a-development-branch`, base `main`.

---

## Self-review

**Spec coverage.** Scope split → the plan's own framing; JSON surface → Task 8; test-only renderer → Task 12; always-bound attempts → Tasks 1 and 4; architecture and `FlowResult` → Tasks 2–5; route surface and single-200 → Task 8; session lifecycle and fail-closed protocol → Task 5; per-request read and boot failure → Task 6; step-up and `RequireAssurance` → Task 11; grace containment, routing table and database-clock expiry → Task 7; last-factor deferral → Global Constraints (arch-tested absence of `revoke()`); errors and timing equalization → Tasks 3 and 10; the lockout ban → Task 9; mutation gate → Task 13; cross-engine matrix → Task 14.

**Gaps found and closed while reviewing.** The spec's `RequireAssurance` section arrived after the first draft of the task list, so Task 11 was added rather than left implied. The lockout ban was a `ScreenBuilder` convention in the first draft and is now a structural scan across four namespaces, per the mid-flight correction.

**Two things this plan states rather than resolves.** Task 11's tests are described in intent with their probes named, not written out in full — the fixtures they need are established in Task 8 and writing them twice would let the two drift. And `AuthFlow`'s private helpers are specified by contract rather than by body, with the one rule that matters stated explicitly: `targetState()` calls the kernel's evaluator and never re-implements satisfiability. Both are deliberate, and both are places a reviewer should look hardest.

**Type consistency.** `SessionBinding::for($id, BindingDomain::X)` is two-argument everywhere after Task 1. `FlowResult` variants are `Continuing`, `Authenticated`, `RecoveryGraceStarted` throughout. `AuthSuccess::amr()` is a method, `->acr` a property. `ScreenSpec` is constructed with named arguments matching Phase 1's actual signature, including `challengePayload` as `?array`.
