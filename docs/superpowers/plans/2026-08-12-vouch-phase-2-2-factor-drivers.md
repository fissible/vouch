# Vouch Phase 2.2 — Factor Contract and Drivers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the `Factor` contract and five authentication drivers — password, TOTP, email OTP, SMS OTP, recovery codes — on top of four versioned amendments to the Phase 2.1 persistence layer, with every single-use mutation owned by the attempt store and every cardinality rule proven atomic on three database engines.

**Architecture:** Drivers validate; they never evaluate policy and never write single-use state. A driver returns a `FactorResult` carrying the kernel's `SatisfiedFactor` plus typed `SingleUseMutation` value objects, and `DatabaseAttemptStore` executes those mutations inside the same transaction as the attempt advance — so a burned recovery code and a failed transition cannot come apart. Enrollment cardinality is serialized behind a per-`(user_id, type)` lock row, because count-then-insert is a read-modify-write that races. Nothing here logs anyone in; the HTTP surface is 2.3.

**Tech Stack:** PHP 8.4, Laravel 13 (`illuminate/*` ^13.0), `spomky-labs/otphp` ^11.5, Orchestra Testbench ^11.0, Pest 3, PHPStan level 9 (Larastan).

## Global Constraints

Copied verbatim from the spec and from 2.1's still-binding rules. Every task's requirements implicitly include this section.

- **PHP `^8.4`.** No lower floor.
- **`Fissible\Vouch\Kernel` may depend only on `php` and `psr/clock`.** Nothing in this phase may add an import to `src/Kernel/`. The regex boundary scans in `tests/Arch/KernelBoundaryTest.php` are the enforcement and must stay green. Note that those scans cover `src/Kernel/` **only** — `new DateTimeImmutable` outside it is permitted and expected.
- **Exactly one new production dependency: `spomky-labs/otphp ^11.5`.** Do not add `spatie/laravel-one-time-passwords`, `laravel/fortify`, `laravel/passkeys`, or `pragmarx/google2fa`. Rejections are recorded in spec §1 and §8; re-adding one silently reverses a reviewed decision.
- **`declare(strict_types=1);` in every PHP file.**
- **PHPStan level 9 over `src` and `tests` must stay clean.** `composer stan` is part of every task's verification, not a final step.
- **Mutation floors unchanged:** `mutate:msi --min=80`, `mutate:covered --min=95`, still scoped to `--class="Fissible\Vouch\Kernel"`. Phase 2 code is out of that scope by design. Do not lower either floor and do not widen the scope.
- **All vouch timestamps are stored in UTC.**
- **Secret material uses Laravel's `encrypted` cast.** Never plaintext. TOTP seeds and password digests are secrets; an OTP code exists only in transit and in `code_hash`.
- **Drivers never evaluate policy.** A driver reports what happened; the kernel decides satisfiability.
- **Drivers never write single-use state.** Every consume, disable, and timestep advance goes through a `SingleUseMutation` executed by the store.
- **Failure reasons are reported truthfully and never pre-redacted.** `ErrorShaper` is the only disclosure boundary.
- **Every new guard must be demonstrated failing against a deliberate violation before being trusted.** A test that passes against a broken implementation is worth less than no test. Where a step says "break it and watch the test fail," that step is not optional.
- **Conventional Commits. Commit by explicit path, never `git add -A`** — `.superpowers/`, `vendor/`, `build/`, `.serena/` are gitignored but untracked scratch is not.
- **Branch:** all work happens on `feat/vouch-2-2-factor-drivers`, branched from `main`.

---

## Verified environment facts

These were established by running real code against real engines before this plan was written. **Do not re-derive them from documentation, and do not "fix" code that looks wrong but matches these findings.**

| Fact | Evidence | Consequence for this plan |
|---|---|---|
| `upsert($rows, $uniqueBy, [])` with an **empty** update array compiles to a plain `INSERT`, not `ON CONFLICT DO NOTHING`. It throws `UniqueConstraintViolationException` on the second call. | Probed on MySQL 8 and Postgres 16. | Use **`insertOrIgnore()`** to claim the lock row. Verified idempotent on all three engines. |
| `lockForUpdate()` on SQLite compiles to a bare `select * from ...` — it is a **no-op**. | `->toSql()` on the SQLite grammar. | SQLite serializes via its own write lock, taken by the `insertOrIgnore`. The mechanism still works, but for a different reason on that engine. Say so in the code comment. |
| A contended lock produces a **`QueryException`** on all three engines, not a clean refusal. | Probed on all three with a 2s timeout. | `EnrollmentGuard` must catch it and map to a typed `EnrollmentRefused`, or callers get a raw driver error. |
| **SQLSTATE alone cannot identify contention.** MySQL and SQLite both report it as `HY000`, the general-error catch-all — and a missing table on SQLite is *also* `HY000`. Only Postgres gives a distinct SQLSTATE. Measured: contention is MySQL `HY000`/**1205**, Postgres **`55P03`**/7, SQLite `HY000`/**5**; a missing table is MySQL `42S02`/1146, Postgres `42P01`/7, SQLite `HY000`/**1**; an unknown column is MySQL `42S22`/1054, Postgres `42703`/7, SQLite `HY000`/**1**. | Probed all three failure modes on all three engines. | Match the **driver code** on MySQL and SQLite and the **SQLSTATE** on Postgres. A blanket `catch (QueryException)` would report a dropped table as routine contention and tell the caller to retry. |
| After the winner commits, a retrying loser observes the committed count and refuses cleanly. | Probed on all three. | Post-condition cardinality check is sufficient and correct. |
| SQLite accepts `ALTER TABLE` adding a `foreignId()->constrained()` column and a composite unique index; Laravel rebuilds the table, the FK **is** enforced afterwards, and `NULL != NULL` holds in the composite unique. | Probed against a file-backed SQLite database. | The four follow-up migrations are safe on all three engines. |
| `otphp`'s `TOTP::verify($otp, $timestamp, $leeway)` returns **`bool` only** — it does not report which timestep matched. With a leeway it checks `$timestamp - $leeway`, `$timestamp`, and `$timestamp + $leeway`. | Read `TOTP.php:136-165` at tag 11.5.0. | The TOTP driver **must not** use the leeway parameter. It iterates candidate timesteps itself and calls `verify($code, $step * $period, null)`, so the matched timestep is known and can be recorded. Amendment B is unimplementable otherwise. |
| `otphp` 11.5.0 is the current release; it requires `psr/clock ^1.0`, which vouch already depends on. Passing `null` for the clock triggers a deprecation. | Packagist + `TOTP.php:20-32`. | Always construct with an explicit `ClockInterface`. |
| `laravel/framework` (installed via Testbench) `replace`s all `illuminate/*` packages, so `illuminate/hashing` and `illuminate/notifications` resolve without a new vendor directory. | `vendor/composer/installed.json`. | Declaring them in `require` is correct and costs nothing. |

---

## File Structure

| File | Responsibility |
|---|---|
| `composer.json` | Adds `spomky-labs/otphp ^11.5`, `illuminate/hashing`, `illuminate/notifications` |
| `config/vouch.php` | New `totp`, `otp`, `recovery`, `enrollment`, `challenges` sections |
| `src/Support/SystemClock.php` | PSR-20 clock backed by Carbon, so `travelTo()` works in tests |
| `src/Secrets/OneTimeSecret.php` | Consume-once, redacting wrapper for bearer material |
| `src/Secrets/SecretAlreadyRevealed.php` | Thrown on a second `reveal()` |
| `database/migrations/2026_08_13_00000{1..4}_*.php` | Amendments A, B, D and the enrollment-lock table |
| `src/Persistence/IdentifierLinkageViolation.php` | Amendment A's three application guards, as one exception type |
| `src/Persistence/ChallengeTargetViolation.php` | Amendment D's challenge-target guard |
| `src/Models/Concerns/GuardsIdentifierLinkage.php` | On `AuthCredential`: same-user + verified checks |
| `src/Models/Concerns/FreezesReferencedValue.php` | On `AuthIdentifier`: value immutability once referenced |
| `src/Models/Concerns/GuardsChallengeTarget.php` | On `AuthChallenge`: credential active, same user, identifier-linked |
| `src/Attempts/Mutations/SingleUseMutation.php` | The mutation interface — `target()` only |
| `src/Attempts/Mutations/{ConsumeChallenge,DisableCredential,AdvanceCredentialTimestep}.php` | The three typed mutations |
| `src/Attempts/ConflictingMutations.php` | Two mutations sharing a `target()` — a programming error |
| `src/Attempts/UnknownMutation.php` | A mutation type the store cannot execute — a programming error |
| `src/Attempts/DatabaseAttemptStore.php` | Amendment C: variadic mutations, executed in-transaction |
| `src/Enrollment/EnrollmentGuard.php` | Per-`(user_id, type)` serialization and the cardinality post-condition |
| `src/Enrollment/EnrollmentRefused.php` | Typed refusal — capacity or contention |
| `src/Enrollment/EnrollmentRefusalReason.php` | Backed enum, two cases |
| `src/Contracts/Factor.php` | The driver contract |
| `src/Contracts/OtpDelivery.php` | Delivery seam — the host wires mail or SMS |
| `src/Factors/{ChallengeRequest,VerificationRequest,EnrollmentResult,FactorResult,FactorFailure}.php` | The contract's value objects |
| `src/Factors/{FactorRegistry,UnknownFactor}.php` | Resolves `auth_credentials.type` to a driver |
| `src/Factors/Drivers/PasswordFactor.php` | Knowledge factor, `Hash` digest |
| `src/Factors/Drivers/RecoveryCodeFactor.php` | Ten single-use codes, `FactorStrength::Recovery` |
| `src/Factors/Drivers/TotpFactor.php` | otphp, explicit timestep resolution |
| `src/Factors/Drivers/OtpFactor.php` | Abstract base for the two OTP drivers |
| `src/Factors/Drivers/{EmailOtpFactor,SmsOtpFactor}.php` | Concrete OTP drivers, differing only in type key and identifier type |
| `src/Notifications/UnconfiguredOtpDelivery.php` | Default binding that throws a directive error rather than dropping codes |
| `src/VouchServiceProvider.php` | Registers the five drivers, the registry, the guard, the delivery default |
| `tests/Secrets/OneTimeSecretTest.php` | Redaction and consume-once |
| `tests/Database/*.php` | Schema, guards, mutations, enrollment |
| `tests/Factors/*.php` | Per-driver enrollment and verification |
| `tests/Concurrency/EnrollmentContentionTest.php` | The hard completion gate |
| `tests/Support/ArrayOtpDelivery.php` | Test double capturing delivered codes |

---

## Task 1: Dependencies, the clock, and `OneTimeSecret`

**Files:**
- Modify: `composer.json`
- Create: `src/Support/SystemClock.php`, `src/Secrets/OneTimeSecret.php`, `src/Secrets/SecretAlreadyRevealed.php`
- Test: `tests/Secrets/OneTimeSecretTest.php`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `Fissible\Vouch\Support\SystemClock implements Psr\Clock\ClockInterface` — `now(): DateTimeImmutable`
  - `Fissible\Vouch\Secrets\OneTimeSecret` — `__construct(string $value)`, `reveal(): string`
  - `Fissible\Vouch\Secrets\SecretAlreadyRevealed extends RuntimeException`

- [ ] **Step 1: Add the three dependencies**

Run exactly this — do not hand-edit `composer.json` version strings:

```bash
composer require spomky-labs/otphp:"^11.5" illuminate/hashing:"^13.0" illuminate/notifications:"^13.0" --no-interaction
```

Expected: `otphp` 11.5.0 installs, pulling `paragonie/constant_time_encoding` and `symfony/deprecation-contracts`. The two `illuminate/*` entries resolve against the already-installed `laravel/framework`, which `replace`s them, so no new vendor directories appear. That is correct, not a failure.

- [ ] **Step 2: Verify the dependency set is exactly what was intended**

```bash
composer show --direct
composer why spomky-labs/otphp
```

Expected: `spomky-labs/otphp` at `11.5.0`. Confirm no `laravel/fortify`, `laravel/passkeys`, `spatie/laravel-one-time-passwords`, or `pragmarx/google2fa` appears anywhere in `composer show`. If one does, stop — a transitive pull would reverse a reviewed decision and must be reported, not worked around.

- [ ] **Step 3: Write the failing test for `OneTimeSecret`**

Create `tests/Secrets/OneTimeSecretTest.php`. This file needs no database, so it must NOT be added to `tests/Pest.php`'s Testbench list.

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Secrets\OneTimeSecret;
use Fissible\Vouch\Secrets\SecretAlreadyRevealed;

const PLAINTEXT = 'otpauth://totp/Acme:ada?secret=JBSWY3DPEHPK3PXP&issuer=Acme';

it('reveals the value exactly once', function (): void {
    $secret = new OneTimeSecret(PLAINTEXT);

    expect($secret->reveal())->toBe(PLAINTEXT);

    $secret->reveal();
})->throws(SecretAlreadyRevealed::class);

/*
 * Each of these is a real path by which bearer material escapes: a log line
 * interpolating the object, a queued job serialising it, an API response
 * json_encoding it, a var_dump in a debug session. None of them involves
 * anyone deciding the secret should be disclosed.
 */
it('never exposes the value through string interpolation', function (): void {
    expect((string) new OneTimeSecret(PLAINTEXT))->toBe('[redacted]')
        ->and("carrying: " . new OneTimeSecret(PLAINTEXT))->not->toContain('JBSWY3DPEHPK3PXP');
});

it('never exposes the value through json encoding', function (): void {
    $encoded = json_encode(['secret' => new OneTimeSecret(PLAINTEXT)]);

    expect($encoded)->toBe('{"secret":"[redacted]"}');
});

it('never exposes the value through php serialization', function (): void {
    expect(serialize(new OneTimeSecret(PLAINTEXT)))->not->toContain('JBSWY3DPEHPK3PXP');
});

it('never exposes the value through var_dump', function (): void {
    ob_start();
    var_dump(new OneTimeSecret(PLAINTEXT));
    $dumped = (string) ob_get_clean();

    expect($dumped)->not->toContain('JBSWY3DPEHPK3PXP');
});

it('does not survive a serialize round trip in usable form', function (): void {
    // Pins the consequence of __serialize() nulling the value: a secret that
    // reached a queue payload is dead on arrival rather than quietly usable.
    $restored = unserialize(serialize(new OneTimeSecret(PLAINTEXT)));

    expect($restored)->toBeInstanceOf(OneTimeSecret::class);

    $restored->reveal();
})->throws(SecretAlreadyRevealed::class);
```

- [ ] **Step 4: Run it and watch it fail**

Run: `vendor/bin/pest tests/Secrets/OneTimeSecretTest.php`
Expected: FAIL — `Class "Fissible\Vouch\Secrets\OneTimeSecret" not found`.

- [ ] **Step 5: Write `SecretAlreadyRevealed`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Secrets;

use RuntimeException;

/**
 * A one-time secret was read twice.
 *
 * Failing loudly is the point. A second read means something kept a reference
 * to bearer material past the single moment it was meant to be displayed, and
 * the alternative — handing it over again — is the quiet leak this class
 * exists to prevent.
 */
final class SecretAlreadyRevealed extends RuntimeException
{
    public static function make(): self
    {
        return new self(
            'This secret has already been revealed and cannot be read again. '
            . 'Enrollment secrets are displayed exactly once; if you need it later, '
            . 'you need a new enrollment, not a second read.',
        );
    }
}
```

- [ ] **Step 6: Write `OneTimeSecret`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Secrets;

use JsonSerializable;
use SensitiveParameter;

/**
 * Bearer material that may be read once and is redacted everywhere else.
 *
 * A provisioning URI or a recovery code authenticates whoever holds it. As a
 * plain string it reaches a log line, a `dd()`, a queued job payload, or an
 * exception context without anyone deciding it should — that is the default
 * behaviour of every debugging tool in the stack, not a hypothetical.
 *
 * This is containment, not a guarantee. `var_export()` and direct reflection
 * still reach a private property, and no PHP object can prevent that. What it
 * closes are the paths that fire by accident.
 *
 * Deliberately NOT readonly: revealing nulls the value, which is the mechanism.
 */
final class OneTimeSecret implements JsonSerializable
{
    private ?string $value;

    public function __construct(#[SensitiveParameter] string $value)
    {
        $this->value = $value;
    }

    /**
     * @throws SecretAlreadyRevealed on the second and every later call.
     */
    public function reveal(): string
    {
        $value = $this->value ?? throw SecretAlreadyRevealed::make();

        $this->value = null;

        return $value;
    }

    public function __toString(): string
    {
        return '[redacted]';
    }

    /**
     * @return array{value: string}
     */
    public function __debugInfo(): array
    {
        return ['value' => '[redacted]'];
    }

    public function jsonSerialize(): string
    {
        return '[redacted]';
    }

    /**
     * Nulls the value rather than redacting it to a string, so a secret that
     * reached a queue or a cache is unusable on the other side instead of
     * arriving as the literal text "[redacted]" and being treated as a code.
     *
     * @return array{value: null}
     */
    public function __serialize(): array
    {
        return ['value' => null];
    }

    /**
     * @param array{value: null} $data
     */
    public function __unserialize(array $data): void
    {
        $this->value = $data['value'];
    }
}
```

- [ ] **Step 7: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Secrets/OneTimeSecretTest.php`
Expected: PASS, 6 tests.

- [ ] **Step 8: Prove the redaction tests are not vacuous**

Temporarily change `jsonSerialize()` to `return (string) $this->value;`. Back up first, per this project's rule against `git checkout --` on work in progress:

```bash
cp src/Secrets/OneTimeSecret.php /tmp/ots.bak
# edit jsonSerialize to leak, then:
vendor/bin/pest tests/Secrets/OneTimeSecretTest.php
```

Expected: the json-encoding test FAILS. If it passes, the assertion is not measuring anything and must be fixed before proceeding. Then restore:

```bash
cp /tmp/ots.bak src/Secrets/OneTimeSecret.php
vendor/bin/pest tests/Secrets/OneTimeSecretTest.php   # green again
```

- [ ] **Step 9: Write `SystemClock`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use DateTimeImmutable;
use Illuminate\Support\Carbon;
use Psr\Clock\ClockInterface;

/**
 * The application clock, as PSR-20.
 *
 * Backed by Carbon rather than `new DateTimeImmutable` so that Laravel's
 * `travelTo()` and `Carbon::setTestNow()` move it. TOTP verification is a
 * function of the current time, and a clock the test suite cannot move would
 * make every timestep assertion depend on when the suite happened to run.
 *
 * This lives outside `src/Kernel/`, so the kernel boundary scan does not apply
 * and Carbon is a legitimate dependency here.
 */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return Carbon::now('UTC')->toDateTimeImmutable();
    }
}
```

- [ ] **Step 10: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green. The pre-existing suite is unaffected by this task.

- [ ] **Step 11: Commit**

```bash
git add composer.json composer.lock src/Support/SystemClock.php src/Secrets tests/Secrets
git commit -m "feat: add otphp, a PSR-20 clock, and the OneTimeSecret wrapper

OneTimeSecret is consume-once and redacts through __toString, __debugInfo,
jsonSerialize and __serialize. Containment rather than a guarantee:
var_export and reflection still reach the private property, which the class
docblock states rather than implies."
```

---

## Task 2: The four Phase 2.1 amendment migrations

**Files:**
- Create: `database/migrations/2026_08_13_000001_add_identifier_id_to_auth_credentials_table.php`
- Create: `database/migrations/2026_08_13_000002_add_last_used_timestep_to_auth_credentials_table.php`
- Create: `database/migrations/2026_08_13_000003_add_credential_id_to_auth_challenges_table.php`
- Create: `database/migrations/2026_08_13_000004_create_auth_enrollment_locks_table.php`
- Modify: `src/Models/AuthCredential.php`, `src/Models/AuthChallenge.php`
- Test: `tests/Database/AmendmentsSchemaTest.php`

**Interfaces:**
- Consumes: nothing
- Produces: columns `auth_credentials.identifier_id`, `auth_credentials.last_used_timestep`, `auth_challenges.credential_id`; table `auth_enrollment_locks (user_id, type)` with unique index `auth_enrollment_locks_user_type_unique`; unique index `auth_cred_user_type_ident_unique` on `auth_credentials (user_id, type, identifier_id)`

These are **follow-up migrations, not edits to 2.1's originals.** The history should show the amendment. Do not consolidate them into the existing files.

- [ ] **Step 1: Write the failing schema test**

Create `tests/Database/AmendmentsSchemaTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

function verifiedIdentifier(int $userId = 7, string $value = 'ada@acme.example'): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);
}

it('adds every amendment column', function (): void {
    expect(Schema::hasColumn('auth_credentials', 'identifier_id'))->toBeTrue()
        ->and(Schema::hasColumn('auth_credentials', 'last_used_timestep'))->toBeTrue()
        ->and(Schema::hasColumn('auth_challenges', 'credential_id'))->toBeTrue()
        ->and(Schema::hasTable('auth_enrollment_locks'))->toBeTrue();
});

it('constrains one otp credential per user, type and identifier', function (): void {
    $identifier = verifiedIdentifier();

    $row = [
        'user_id' => 7,
        'type' => 'email_otp',
        'identifier_id' => $identifier->id,
        'strength' => 'possession_weak',
    ];

    AuthCredential::create($row);
    AuthCredential::create($row);
})->throws(\Illuminate\Database\QueryException::class);

it('leaves null-identifier credentials unconstrained, which is deliberate here', function (): void {
    /*
     * The inverse of the 2.1 session-binding case, where NULL != NULL broke a
     * constraint by permitting multiple live rows. Here it is exactly right:
     * password, TOTP, recovery and passkey rows carry NULL and are bounded by
     * maxActiveCredentials() instead. This test exists so the next reader does
     * not "fix" it back into the 2.1 mistake.
     */
    $row = ['user_id' => 7, 'type' => 'password', 'identifier_id' => null, 'strength' => 'knowledge'];

    AuthCredential::create($row);
    AuthCredential::create($row);

    expect(AuthCredential::where('user_id', 7)->where('type', 'password')->count())->toBe(2);
});

it('refuses to delete an identifier that a credential references', function (): void {
    $identifier = verifiedIdentifier();

    AuthCredential::create([
        'user_id' => 7,
        'type' => 'email_otp',
        'identifier_id' => $identifier->id,
        'strength' => 'possession_weak',
    ]);

    $identifier->delete();
})->throws(\Illuminate\Database\QueryException::class);

it('stores a timestep as an integer, not a timestamp', function (): void {
    $credential = AuthCredential::create([
        'user_id' => 7,
        'type' => 'totp',
        'strength' => 'possession',
        'last_used_timestep' => 58_400_123,
    ]);

    expect(AuthCredential::findOrFail($credential->id)->last_used_timestep)->toBe(58_400_123);
});

it('permits exactly one enrollment lock row per user and type', function (): void {
    DB::table('auth_enrollment_locks')->insert(['user_id' => 7, 'type' => 'password']);
    DB::table('auth_enrollment_locks')->insert(['user_id' => 7, 'type' => 'password']);
})->throws(\Illuminate\Database\QueryException::class);

it('treats a repeated lock claim as a no-op rather than an error', function (): void {
    // insertOrIgnore is how EnrollmentGuard claims the row. Verified idempotent
    // on SQLite, MySQL and Postgres; upsert() with an empty update array is NOT
    // -- it compiles to a plain INSERT and throws on the second call.
    DB::table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);
    DB::table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);

    expect(DB::table('auth_enrollment_locks')->count())->toBe(1);
});
```

- [ ] **Step 2: Run it and watch it fail**

Run: `vendor/bin/pest tests/Database/AmendmentsSchemaTest.php`
Expected: FAIL — the columns do not exist.

- [ ] **Step 3: Write Amendment A's migration**

`database/migrations/2026_08_13_000001_add_identifier_id_to_auth_credentials_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Amendment A to Phase 2.1 (spec 2026-08-12 §4).
 *
 * OTP credentials must reference the address they deliver to. The kernel's
 * require_distinct_credentials keys on credentialId, so a factor with no
 * credential cannot participate in distinctness — OTP therefore needs credential
 * rows, and their identity IS the destination address. Overloading
 * authenticator_id would corrupt require_independent_authenticators, which
 * consumes it for a different purpose.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('auth_credentials', function (Blueprint $table): void {
            /*
             * restrictOnDelete, not cascade. An address that ever served as an
             * authentication destination is permanent audit history. This blocks
             * deletion regardless of disabled_at, so "disabled, therefore
             * deletable" is FALSE — there is no retirement workflow in v1.
             */
            $table->foreignId('identifier_id')->nullable()
                ->constrained('auth_identifiers')
                ->restrictOnDelete();

            /*
             * NULL semantics here are the INVERSE of the 2.1 session-binding
             * case, and this looks like the mistake that was just fixed. It is
             * not. There, NULL != NULL broke the constraint by permitting
             * multiple live rows. Here it is exactly what is wanted: OTP
             * credentials always carry a non-null identifier_id and are
             * constrained to one per address; password, TOTP, recovery and
             * passkey rows carry NULL and are bounded by maxActiveCredentials()
             * instead, enforced by EnrollmentGuard rather than by this index.
             *
             * Explicit index name: the generated one would be
             * auth_credentials_user_id_type_identifier_id_unique, and 2.1 set the
             * precedent of naming composite indexes rather than relying on
             * generation near MySQL's 64-character limit.
             */
            $table->unique(['user_id', 'type', 'identifier_id'], 'auth_cred_user_type_ident_unique');
        });
    }

    public function down(): void
    {
        Schema::table('auth_credentials', function (Blueprint $table): void {
            $table->dropUnique('auth_cred_user_type_ident_unique');
            $table->dropConstrainedForeignId('identifier_id');
        });
    }
};
```

- [ ] **Step 4: Write Amendment B's migration**

`database/migrations/2026_08_13_000002_add_last_used_timestep_to_auth_credentials_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Amendment B to Phase 2.1 (spec 2026-08-12 §4).
 *
 * RFC 6238 §5.2 requires that an accepted OTP not be accepted a second time,
 * and a wall-clock last_used_at cannot recover WHICH timestep was accepted once
 * a leeway window is allowed: a code from timestep T+1 can be accepted while the
 * wall clock sits in period T, so deriving the timestep from last_used_at yields
 * T, and replaying the T+1 code passes a `>` check again. The guard would look
 * correct and permit the exact replay the RFC forbids.
 *
 * last_used_at remains operational metadata. It is not the security guard.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('auth_credentials', function (Blueprint $table): void {
            $table->unsignedBigInteger('last_used_timestep')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('auth_credentials', function (Blueprint $table): void {
            $table->dropColumn('last_used_timestep');
        });
    }
};
```

- [ ] **Step 5: Write Amendment D's migration**

`database/migrations/2026_08_13_000003_add_credential_id_to_auth_challenges_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Amendment D to Phase 2.1 (spec 2026-08-12 §4).
 *
 * auth_challenges recorded attempt_id and factor_type and nothing about WHAT was
 * challenged. For OTP that is a hole: challenge() selects a verified identifier
 * and delivers a code to it, then verify() succeeds and must report a
 * SatisfiedFactor.credentialId. With no persisted target that credential is
 * chosen after the fact, so a user with OTP on two addresses could have a code
 * delivered to one and attributed to the other — and require_distinct_credentials
 * would then be keyed on something that never happened, while still passing.
 *
 * Nullable at the column, required for OTP at the application layer
 * (GuardsChallengeTarget): password and TOTP challenges have no delivery target,
 * so NOT NULL would be a lie.
 *
 * cascadeOnDelete, unlike Amendment A's restrictOnDelete: challenges are
 * ephemeral and swept, this is the credential's OWN deletion rather than an
 * identifier's, and an orphaned challenge is useless rather than historic.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('auth_challenges', function (Blueprint $table): void {
            $table->foreignId('credential_id')->nullable()
                ->constrained('auth_credentials')
                ->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::table('auth_challenges', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('credential_id');
        });
    }
};
```

- [ ] **Step 6: Write the enrollment-lock migration**

`database/migrations/2026_08_13_000004_create_auth_enrollment_locks_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Serialization anchor for credential enrollment (spec 2026-08-12 §2).
 *
 * maxActiveCredentials() is count-then-insert, which is a read-modify-write:
 * two concurrent enrollments each observe capacity and each proceed. Row locks
 * alone cannot fix it — SELECT ... FOR UPDATE over auth_credentials locks the
 * rows that exist, and the first-enrollment race is precisely the case where
 * there are none. Hence a dedicated row per (user_id, type) that always exists
 * before the count is taken.
 *
 * No id, no timestamps: this is a mutex anchor, not a record. Rows are claimed
 * with insertOrIgnore, never deleted, and carry no state beyond their existence.
 *
 * A unique index rather than a composite primary key, because insertOrIgnore's
 * conflict behaviour was verified against this exact shape on SQLite, MySQL 8
 * and Postgres 16.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_enrollment_locks', function (Blueprint $table): void {
            $table->unsignedBigInteger('user_id');
            $table->string('type', 32);

            $table->unique(['user_id', 'type'], 'auth_enrollment_locks_user_type_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_enrollment_locks');
    }
};
```

- [ ] **Step 7: Update the two models' docblocks and casts**

In `src/Models/AuthCredential.php`, add to the class docblock, after `@property string $type`:

```php
 * @property int|null $identifier_id
```

and after `@property Carbon|null $last_used_at`:

```php
 * @property int|null $last_used_timestep
```

Then add to the `casts()` array, so the timestep is an int rather than a numeric string:

```php
            'last_used_timestep' => 'integer',
```

In `src/Models/AuthChallenge.php`, add to the class docblock after `@property string $factor_type`:

```php
 * @property int|null $credential_id
```

- [ ] **Step 8: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Database/AmendmentsSchemaTest.php`
Expected: PASS, 7 tests.

- [ ] **Step 9: Verify the migrations roll back cleanly**

A `down()` that does not work is a `down()` nobody can trust in a rollout.

```bash
vendor/bin/testbench migrate:fresh --database=sqlite
vendor/bin/testbench migrate:rollback --step=4 --database=sqlite
vendor/bin/testbench migrate --database=sqlite
```

Expected: all three succeed. If `dropConstrainedForeignId` fails on SQLite, report it rather than deleting the `down()` — a rollback that silently does nothing is worse than one that errors.

- [ ] **Step 10: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 11: Commit**

```bash
git add database/migrations src/Models/AuthCredential.php src/Models/AuthChallenge.php tests/Database/AmendmentsSchemaTest.php
git commit -m "feat: land Phase 2.1 amendments A, B and D plus the enrollment lock table

Follow-up migrations rather than edits to 2.1's originals, so the history
shows the amendment. Amendment A's NULL semantics are the inverse of the 2.1
session-binding fix and are commented as such, because they look like the
mistake that was just corrected."
```

---

## Task 3: Amendment A's three application-level guards

**Files:**
- Create: `src/Persistence/IdentifierLinkageViolation.php`, `src/Models/Concerns/GuardsIdentifierLinkage.php`, `src/Models/Concerns/FreezesReferencedValue.php`
- Modify: `src/Models/AuthCredential.php`, `src/Models/AuthIdentifier.php`
- Test: `tests/Database/IdentifierLinkageTest.php`

**Interfaces:**
- Consumes: `auth_credentials.identifier_id` from Task 2
- Produces: `Fissible\Vouch\Persistence\IdentifierLinkageViolation extends InvalidArgumentException` with static constructors `crossUser()`, `unverified()`, `missing()`, `frozen()`

No foreign key can express these three rules, and they belong in the model layer for the same reason `EnforcesValueBounds` does: a docblock constrains nobody, and a driver-level check is bypassed by the next piece of code that writes a credential directly.

- [ ] **Step 1: Write the failing test**

Create `tests/Database/IdentifierLinkageTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Persistence\IdentifierLinkageViolation;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function identifierFor(int $userId, string $value, bool $verified = true): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => $verified ? now() : null,
    ]);
}

function otpCredential(int $userId, AuthIdentifier $identifier): AuthCredential
{
    return AuthCredential::create([
        'user_id' => $userId,
        'type' => 'email_otp',
        'identifier_id' => $identifier->id,
        'strength' => 'possession_weak',
    ]);
}

it('links a credential to a verified identifier owned by the same user', function (): void {
    $identifier = identifierFor(7, 'ada@acme.example');

    expect(otpCredential(7, $identifier)->identifier_id)->toBe($identifier->id);
});

it('refuses to link a credential to another user identifier', function (): void {
    // Two independent foreign keys cannot relate user_id to the identifier's
    // owner. Without this check, an OTP credential on user 7 could deliver codes
    // to user 8's verified address.
    otpCredential(7, identifierFor(8, 'grace@acme.example'));
})->throws(IdentifierLinkageViolation::class);

it('refuses to link a credential to an unverified identifier', function (): void {
    // An unverified identifier is attacker-supplied until proven. Linking OTP
    // delivery to one routes codes to an address nobody has demonstrated control of.
    otpCredential(7, identifierFor(7, 'unproven@acme.example', verified: false));
})->throws(IdentifierLinkageViolation::class);

it('refuses to link a credential to an identifier that does not exist', function (): void {
    AuthCredential::create([
        'user_id' => 7,
        'type' => 'email_otp',
        'identifier_id' => 999_999,
        'strength' => 'possession_weak',
    ]);
})->throws(IdentifierLinkageViolation::class);

it('permits a credential with no identifier at all', function (): void {
    $credential = AuthCredential::create([
        'user_id' => 7,
        'type' => 'password',
        'secret' => 'digest',
        'strength' => 'knowledge',
    ]);

    expect($credential->identifier_id)->toBeNull();
});

it('freezes an identifier value once a credential references it', function (): void {
    /*
     * The account-takeover path this closes: mutating the address in place
     * silently redirects every existing OTP credential pointing at that row, so
     * an attacker who can edit a profile field receives all future codes without
     * touching a single credential.
     */
    $identifier = identifierFor(7, 'ada@acme.example');
    otpCredential(7, $identifier);

    $identifier->update(['value' => 'attacker@evil.example']);
})->throws(IdentifierLinkageViolation::class);

it('still permits editing an identifier no credential references', function (): void {
    $identifier = identifierFor(7, 'typo@acme.example');

    $identifier->update(['value' => 'fixed@acme.example']);

    expect(AuthIdentifier::findOrFail($identifier->id)->value)->toBe('fixed@acme.example');
});

it('still permits editing other columns of a referenced identifier', function (): void {
    // Only `value` is frozen. Freezing the whole row would block re-verification
    // and primary-address changes, neither of which redirects delivery.
    $identifier = identifierFor(7, 'ada@acme.example');
    otpCredential(7, $identifier);

    $identifier->update(['is_primary' => true]);

    expect(AuthIdentifier::findOrFail($identifier->id)->is_primary)->toBeTrue();
});

it('freezes the value even when the referencing credential is disabled', function (): void {
    // restrictOnDelete blocks deletion regardless of disabled_at, and the same
    // logic applies to mutation: a disabled credential can be re-enabled, so its
    // delivery target must not have moved underneath it in the meantime.
    $identifier = identifierFor(7, 'ada@acme.example');
    $credential = otpCredential(7, $identifier);
    $credential->update(['disabled_at' => now()]);

    $identifier->update(['value' => 'attacker@evil.example']);
})->throws(IdentifierLinkageViolation::class);
```

- [ ] **Step 2: Run it and watch it fail**

Run: `vendor/bin/pest tests/Database/IdentifierLinkageTest.php`
Expected: FAIL — `IdentifierLinkageViolation` not found, and the cross-user and unverified cases currently succeed.

- [ ] **Step 3: Write the exception**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Persistence;

use InvalidArgumentException;

/**
 * A credential-to-identifier link broke one of Amendment A's three rules.
 *
 * None of these can be expressed as a foreign key: same-user relates two
 * independent FKs to each other, verified is a column value rather than a
 * reference, and immutability is a rule about updates rather than about rows.
 */
final class IdentifierLinkageViolation extends InvalidArgumentException
{
    public static function missing(int $identifierId): self
    {
        return new self(sprintf(
            'Identifier %d does not exist, so no credential may reference it.',
            $identifierId,
        ));
    }

    public static function crossUser(int $credentialUserId, int $identifierUserId): self
    {
        return new self(sprintf(
            'Refusing to link a credential owned by user %d to an identifier owned by user %d. '
            . 'An OTP credential delivers to its identifier, so a cross-user link routes '
            . 'authentication codes to somebody else.',
            $credentialUserId,
            $identifierUserId,
        ));
    }

    public static function unverified(int $identifierId): self
    {
        return new self(sprintf(
            'Identifier %d is not verified. An unverified identifier is attacker-supplied '
            . 'until proven, and linking OTP delivery to one routes codes to an address '
            . 'nobody has demonstrated control of.',
            $identifierId,
        ));
    }

    public static function frozen(int $identifierId): self
    {
        return new self(sprintf(
            'Identifier %d is referenced by at least one credential, so its value is frozen. '
            . 'Mutating it in place would silently redirect every OTP credential pointing at '
            . 'this row — an account takeover requiring no credential change at all. Create '
            . 'and verify a new identifier, then enroll a new credential against it.',
            $identifierId,
        ));
    }
}
```

- [ ] **Step 4: Write `GuardsIdentifierLinkage`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models\Concerns;

use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Persistence\IdentifierLinkageViolation;

/**
 * Enforces Amendment A's same-user and verified rules on the credential write path.
 *
 * In the model layer rather than in a driver, following EnforcesValueBounds and
 * for the same reason: a check that lives in one caller is a check the next
 * caller skips. Hooking `saving` means every create and update goes through it.
 */
trait GuardsIdentifierLinkage
{
    public static function bootGuardsIdentifierLinkage(): void
    {
        static::saving(static function (self $model): void {
            $identifierId = $model->getAttribute('identifier_id');

            if ($identifierId === null) {
                return;
            }

            $identifierId = (int) $identifierId;
            $identifier = AuthIdentifier::query()->find($identifierId);

            if (! $identifier instanceof AuthIdentifier) {
                throw IdentifierLinkageViolation::missing($identifierId);
            }

            $credentialUserId = (int) $model->getAttribute('user_id');

            if ($identifier->user_id !== $credentialUserId) {
                throw IdentifierLinkageViolation::crossUser($credentialUserId, $identifier->user_id);
            }

            if ($identifier->verified_at === null) {
                throw IdentifierLinkageViolation::unverified($identifierId);
            }
        });
    }
}
```

- [ ] **Step 5: Write `FreezesReferencedValue`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models\Concerns;

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Persistence\IdentifierLinkageViolation;

/**
 * Freezes AuthIdentifier::$value once any credential references the row.
 *
 * `updating` rather than `saving`: on create nothing can reference the row yet,
 * and hooking `saving` would cost a query on every insert to learn that.
 *
 * Only `value` freezes. Freezing the whole row would block re-verification and
 * primary-address changes, neither of which redirects delivery, and a guard that
 * blocks legitimate work gets removed.
 *
 * The disabled_at state of the referencing credential is deliberately not
 * considered: a disabled credential can be re-enabled, so its delivery target
 * must not have moved underneath it in the meantime.
 */
trait FreezesReferencedValue
{
    public static function bootFreezesReferencedValue(): void
    {
        static::updating(static function (self $model): void {
            if (! $model->isDirty('value')) {
                return;
            }

            $referenced = AuthCredential::query()
                ->where('identifier_id', $model->getKey())
                ->exists();

            if ($referenced) {
                throw IdentifierLinkageViolation::frozen((int) $model->getKey());
            }
        });
    }
}
```

- [ ] **Step 6: Compose the traits onto the models**

In `src/Models/AuthCredential.php`, add the import and `use` statement:

```php
use Fissible\Vouch\Models\Concerns\GuardsIdentifierLinkage;
```

```php
final class AuthCredential extends Model
{
    use GuardsIdentifierLinkage;
```

In `src/Models/AuthIdentifier.php`, add alongside the existing `EnforcesValueBounds`:

```php
use Fissible\Vouch\Models\Concerns\FreezesReferencedValue;
```

```php
final class AuthIdentifier extends Model
{
    use EnforcesValueBounds;
    use FreezesReferencedValue;
```

- [ ] **Step 7: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Database/IdentifierLinkageTest.php`
Expected: PASS, 9 tests.

- [ ] **Step 8: Prove each guard is load-bearing**

Three separate probes. Back up before each edit and restore after:

```bash
cp src/Models/Concerns/GuardsIdentifierLinkage.php /tmp/gil.bak
cp src/Models/Concerns/FreezesReferencedValue.php /tmp/frv.bak
```

1. Comment out the `crossUser` throw → the cross-user test must FAIL.
2. Comment out the `unverified` throw → the unverified test must FAIL.
3. Change `FreezesReferencedValue`'s `updating` to check `disabled_at IS NULL` on the referencing credential → the disabled-credential test must FAIL.

If any of these still passes, that assertion is measuring nothing. Restore after each:

```bash
cp /tmp/gil.bak src/Models/Concerns/GuardsIdentifierLinkage.php
cp /tmp/frv.bak src/Models/Concerns/FreezesReferencedValue.php
vendor/bin/pest tests/Database/IdentifierLinkageTest.php   # green again
```

- [ ] **Step 9: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 10: Commit**

```bash
git add src/Persistence/IdentifierLinkageViolation.php src/Models/Concerns/GuardsIdentifierLinkage.php src/Models/Concerns/FreezesReferencedValue.php src/Models/AuthCredential.php src/Models/AuthIdentifier.php tests/Database/IdentifierLinkageTest.php
git commit -m "feat: enforce Amendment A's same-user, verified and immutability rules

Model-layer hooks rather than driver checks, following EnforcesValueBounds:
a check that lives in one caller is a check the next caller skips. Value
immutability holds even when the referencing credential is disabled, because
a disabled credential can be re-enabled."
```

---

## Task 4: Amendment D's challenge-target guard

**Files:**
- Create: `src/Persistence/ChallengeTargetViolation.php`, `src/Models/Concerns/GuardsChallengeTarget.php`
- Modify: `src/Models/AuthChallenge.php`, `config/vouch.php`
- Test: `tests/Database/ChallengeTargetTest.php`

**Interfaces:**
- Consumes: `auth_challenges.credential_id` from Task 2; `auth_credentials.identifier_id` from Task 2
- Produces: `Fissible\Vouch\Persistence\ChallengeTargetViolation extends InvalidArgumentException` with `targetRequired()`, `missing()`, `disabled()`, `foreignUser()`, `notIdentifierLinked()`; config key `vouch.challenges.require_credential`

- [ ] **Step 1: Add the config section**

In `config/vouch.php`, add before the closing `];`:

```php
    'challenges' => [
        /*
         * Factor types whose challenges MUST name the credential they were
         * delivered against. Configured rather than hardcoded so 2.2b can add
         * passkey without editing a model.
         *
         * Password and TOTP are absent deliberately: they issue no challenge and
         * have no delivery target, so requiring one would be a lie.
         */
        'require_credential' => ['email_otp', 'sms_otp'],
    ],
```

- [ ] **Step 2: Write the failing test**

Create `tests/Database/ChallengeTargetTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Persistence\ChallengeTargetViolation;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function targetAttempt(?int $userId = 7): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => $userId,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ]);
}

function targetCredential(int $userId = 7, string $value = 'ada@acme.example'): AuthCredential
{
    $identifier = AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);

    return AuthCredential::create([
        'user_id' => $userId,
        'type' => 'email_otp',
        'identifier_id' => $identifier->id,
        'strength' => 'possession_weak',
    ]);
}

/**
 * @param array<string, mixed> $overrides
 */
function makeChallenge(array $overrides = []): AuthChallenge
{
    return AuthChallenge::create(array_merge([
        'attempt_id' => targetAttempt()->id,
        'factor_type' => 'email_otp',
        'code_hash' => 'digest',
        'expires_at' => now()->addMinutes(2),
    ], $overrides));
}

it('records the credential an otp challenge was delivered against', function (): void {
    $attempt = targetAttempt();
    $credential = targetCredential();

    $challenge = makeChallenge(['attempt_id' => $attempt->id, 'credential_id' => $credential->id]);

    expect(AuthChallenge::findOrFail($challenge->id)->credential_id)->toBe($credential->id);
});

it('refuses an otp challenge with no credential target', function (): void {
    /*
     * Without this, verify() would pick a credential after the fact from
     * whatever the user currently has. A user with OTP on two addresses could
     * have a code delivered to one and attributed to the other, and
     * require_distinct_credentials would then pass while describing something
     * that never happened.
     */
    makeChallenge(['credential_id' => null]);
})->throws(ChallengeTargetViolation::class);

it('permits a password challenge with no credential target', function (): void {
    // Password and TOTP issue no challenge and have no delivery target. A
    // NOT NULL column would be a lie; this is where the distinction lives.
    $challenge = makeChallenge(['factor_type' => 'password', 'credential_id' => null]);

    expect($challenge->credential_id)->toBeNull();
});

it('refuses a challenge naming a disabled credential', function (): void {
    $credential = targetCredential();
    $credential->update(['disabled_at' => now()]);

    makeChallenge(['credential_id' => $credential->id]);
})->throws(ChallengeTargetViolation::class);

it('refuses a challenge naming another user credential', function (): void {
    $attempt = targetAttempt(userId: 7);
    $credential = targetCredential(userId: 8, value: 'grace@acme.example');

    makeChallenge(['attempt_id' => $attempt->id, 'credential_id' => $credential->id]);
})->throws(ChallengeTargetViolation::class);

it('refuses a challenge naming a credential with no identifier', function (): void {
    // An OTP credential with no identifier has nowhere to deliver to. Accepting
    // it would mean a challenge whose target cannot be resolved.
    $credential = AuthCredential::create([
        'user_id' => 7,
        'type' => 'email_otp',
        'identifier_id' => null,
        'strength' => 'possession_weak',
    ]);

    makeChallenge(['credential_id' => $credential->id]);
})->throws(ChallengeTargetViolation::class);

it('refuses a challenge on an attempt with no identified user', function (): void {
    // Anonymous attempts cannot own a credential-bound challenge; permitting one
    // would skip the same-user check entirely.
    $attempt = targetAttempt(userId: null);

    makeChallenge(['attempt_id' => $attempt->id, 'credential_id' => targetCredential()->id]);
})->throws(ChallengeTargetViolation::class);
```

- [ ] **Step 3: Run it and watch it fail**

Run: `vendor/bin/pest tests/Database/ChallengeTargetTest.php`
Expected: FAIL — `ChallengeTargetViolation` not found.

- [ ] **Step 4: Write the exception**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Persistence;

use InvalidArgumentException;

/**
 * A challenge named an unusable delivery target, or named none when one was required.
 *
 * The challenge row is the record of what was actually sent. If it can be
 * created without a valid target, verification has nothing authoritative to
 * compare against and the satisfied credential is reconstructed by guesswork.
 */
final class ChallengeTargetViolation extends InvalidArgumentException
{
    public static function targetRequired(string $factorType): self
    {
        return new self(sprintf(
            'A %s challenge must name the credential it was delivered against. Without one, '
            . 'the satisfied credential is chosen after the fact and kernel distinctness '
            . 'describes a delivery that never happened.',
            $factorType,
        ));
    }

    public static function missing(int $credentialId): self
    {
        return new self(sprintf('Credential %d does not exist.', $credentialId));
    }

    public static function disabled(int $credentialId): self
    {
        return new self(sprintf(
            'Credential %d is disabled and must not receive a challenge.',
            $credentialId,
        ));
    }

    public static function foreignUser(int $credentialId, ?int $attemptUserId): self
    {
        return new self(sprintf(
            'Credential %d does not belong to the attempt user (%s). A challenge delivered '
            . 'against another user credential would authenticate the wrong account.',
            $credentialId,
            $attemptUserId === null ? 'the attempt has no identified user' : (string) $attemptUserId,
        ));
    }

    public static function notIdentifierLinked(int $credentialId): self
    {
        return new self(sprintf(
            'Credential %d has no identifier, so there is nowhere to deliver a code.',
            $credentialId,
        ));
    }
}
```

- [ ] **Step 5: Write `GuardsChallengeTarget`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models\Concerns;

use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Persistence\ChallengeTargetViolation;
use Illuminate\Support\Facades\Config;

/**
 * Enforces Amendment D on the challenge write path.
 *
 * `creating` rather than `saving`: a challenge's target is fixed at delivery.
 * The only later writes are consumption and the attempt counter, neither of
 * which may change what was sent, and re-running the checks on those would cost
 * two queries per verification for an invariant that cannot have changed.
 */
trait GuardsChallengeTarget
{
    public static function bootGuardsChallengeTarget(): void
    {
        static::creating(static function (self $model): void {
            $factorType = (string) $model->getAttribute('factor_type');
            $credentialId = $model->getAttribute('credential_id');

            /** @var list<string> $requiresTarget */
            $requiresTarget = Config::array('vouch.challenges.require_credential');

            if ($credentialId === null) {
                if (in_array($factorType, $requiresTarget, true)) {
                    throw ChallengeTargetViolation::targetRequired($factorType);
                }

                return;
            }

            $credentialId = (int) $credentialId;
            $credential = AuthCredential::query()->find($credentialId);

            if (! $credential instanceof AuthCredential) {
                throw ChallengeTargetViolation::missing($credentialId);
            }

            if ($credential->disabled_at !== null) {
                throw ChallengeTargetViolation::disabled($credentialId);
            }

            $attempt = AuthAttempt::query()->find($model->getAttribute('attempt_id'));
            $attemptUserId = $attempt?->user_id;

            if ($attemptUserId === null || $credential->user_id !== $attemptUserId) {
                throw ChallengeTargetViolation::foreignUser($credentialId, $attemptUserId);
            }

            /*
             * The identifier is derived through the credential rather than
             * stored on the challenge as well, so the two cannot drift. This
             * check is what makes that derivation total.
             */
            if (in_array($factorType, $requiresTarget, true) && $credential->identifier_id === null) {
                throw ChallengeTargetViolation::notIdentifierLinked($credentialId);
            }
        });
    }
}
```

- [ ] **Step 6: Compose the trait onto `AuthChallenge`**

In `src/Models/AuthChallenge.php`:

```php
use Fissible\Vouch\Models\Concerns\GuardsChallengeTarget;
```

```php
final class AuthChallenge extends Model
{
    use GuardsChallengeTarget;
```

- [ ] **Step 7: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Database/ChallengeTargetTest.php`
Expected: PASS, 7 tests.

- [ ] **Step 8: Fix the pre-existing challenge fixtures**

`tests/Database/AttemptsAndChallengesTest.php` and `tests/Concurrency/AttemptStoreContentionTest.php` both create `email_otp` challenges with no `credential_id`, which this guard now correctly refuses. They are testing challenge mechanics rather than OTP delivery, so change their `factor_type` from `'email_otp'` to `'password'` — the honest fix, since those fixtures were never about a delivered code.

Run: `composer test`
Expected: green. If any test still fails because it genuinely needs an OTP challenge, give it a real credential target rather than weakening the guard.

- [ ] **Step 9: Prove the guard is load-bearing**

```bash
cp src/Models/Concerns/GuardsChallengeTarget.php /tmp/gct.bak
```

Comment out the `targetRequired` throw. The "refuses an otp challenge with no credential target" test must FAIL. Then restore:

```bash
cp /tmp/gct.bak src/Models/Concerns/GuardsChallengeTarget.php
vendor/bin/pest tests/Database/ChallengeTargetTest.php   # green again
```

- [ ] **Step 10: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 11: Commit**

```bash
git add src/Persistence/ChallengeTargetViolation.php src/Models/Concerns/GuardsChallengeTarget.php src/Models/AuthChallenge.php config/vouch.php tests/Database/ChallengeTargetTest.php tests/Database/AttemptsAndChallengesTest.php tests/Concurrency/AttemptStoreContentionTest.php
git commit -m "feat: require and validate a challenge's credential target for OTP

The challenge row is the record of what was actually sent. Pre-existing
fixtures that created credential-less email_otp challenges were testing
challenge mechanics, not delivery, so they move to factor_type password
rather than the guard being weakened to accommodate them."
```

---

## Task 5: Typed single-use mutations and the store rewrite (Amendment C)

**Files:**
- Create: `src/Attempts/Mutations/SingleUseMutation.php`, `src/Attempts/Mutations/ConsumeChallenge.php`, `src/Attempts/Mutations/DisableCredential.php`, `src/Attempts/Mutations/AdvanceCredentialTimestep.php`, `src/Attempts/ConflictingMutations.php`, `src/Attempts/UnknownMutation.php`
- Modify: `src/Contracts/AttemptStore.php`, `src/Attempts/DatabaseAttemptStore.php`, `src/Attempts/TransitionOutcome.php`
- Modify: `tests/Database/AttemptStoreTest.php`, `tests/Concurrency/AttemptStoreContentionTest.php`
- Test: `tests/Database/MutationStoreTest.php`

**Interfaces:**
- Consumes: `auth_credentials.last_used_timestep` from Task 2
- Produces:
  - `Fissible\Vouch\Attempts\Mutations\SingleUseMutation` — `target(): string`
  - `ConsumeChallenge(int $challengeId, int $attemptId)`, `DisableCredential(int $credentialId)`, `AdvanceCredentialTimestep(int $credentialId, int $timestep)`
  - `AttemptStore::transition(AuthAttempt $attempt, AttemptState $to, SingleUseMutation ...$mutations): TransitionOutcome`
  - `TransitionOutcome::CredentialAlreadyConsumed`, `TransitionOutcome::TimestepReplay`
  - `Fissible\Vouch\Attempts\ConflictingMutations`, `Fissible\Vouch\Attempts\UnknownMutation` — both `LogicException`

This is the breaking signature change. The only callers today are tests, which this task updates.

- [ ] **Step 1: Write the failing test**

Create `tests/Database/MutationStoreTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\ConflictingMutations;
use Fissible\Vouch\Attempts\Mutations\AdvanceCredentialTimestep;
use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Attempts\Mutations\DisableCredential;
use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Attempts\UnknownMutation;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @param array<string, mixed> $overrides
 */
function mutableAttempt(array $overrides = []): AuthAttempt
{
    return AuthAttempt::create(array_merge([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => 7,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ], $overrides));
}

function recoveryCredential(): AuthCredential
{
    return AuthCredential::create([
        'user_id' => 7,
        'type' => 'recovery_code',
        'secret' => 'digest',
        'strength' => 'recovery',
    ]);
}

function totpCredential(?int $timestep = null): AuthCredential
{
    return AuthCredential::create([
        'user_id' => 7,
        'type' => 'totp',
        'secret' => 'JBSWY3DPEHPK3PXP',
        'strength' => 'possession',
        'last_used_timestep' => $timestep,
    ]);
}

it('disables a credential atomically with the transition', function (): void {
    $attempt = mutableAttempt();
    $credential = recoveryCredential();

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new DisableCredential($credential->id),
    );

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and(AuthCredential::findOrFail($credential->id)->disabled_at)->not->toBeNull()
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(2);
});

it('refuses to disable an already-disabled credential and advances nothing', function (): void {
    $attempt = mutableAttempt();
    $credential = recoveryCredential();
    $credential->update(['disabled_at' => now()]);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new DisableCredential($credential->id),
    );

    expect($outcome)->toBe(TransitionOutcome::CredentialAlreadyConsumed)
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(1);
});

it('rolls the credential disable back when the transition loses', function (): void {
    /*
     * The most valuable test here, and the reason single-use state belongs to
     * the store at all: without the rollback, a lost race burns a recovery code
     * while the user stays unauthenticated. That is a denial of service against
     * a legitimate user, and it is invisible to any test that only asserts on
     * the returned outcome.
     */
    $attempt = mutableAttempt();
    $credential = recoveryCredential();

    // Stale version: the caller's in-memory attempt lost the CAS.
    $stale = AuthAttempt::findOrFail($attempt->id);
    AuthAttempt::where('id', $attempt->id)->update(['version' => 5]);

    $outcome = app(AttemptStore::class)->transition(
        $stale,
        AttemptState::FactorSatisfied,
        new DisableCredential($credential->id),
    );

    expect($outcome)->toBe(TransitionOutcome::ConcurrentModification)
        ->and(AuthCredential::findOrFail($credential->id)->disabled_at)->toBeNull();
});

it('advances a timestep forward', function (): void {
    $attempt = mutableAttempt();
    $credential = totpCredential(timestep: 100);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 101),
    );

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and(AuthCredential::findOrFail($credential->id)->last_used_timestep)->toBe(101);
});

it('refuses to replay a timestep already used', function (): void {
    $attempt = mutableAttempt();
    $credential = totpCredential(timestep: 100);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 100),
    );

    expect($outcome)->toBe(TransitionOutcome::TimestepReplay)
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(1);
});

it('refuses to move a timestep backwards', function (): void {
    // A clock that jumped back must not reopen an already-spent window.
    $attempt = mutableAttempt();
    $credential = totpCredential(timestep: 100);

    expect(app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 99),
    ))->toBe(TransitionOutcome::TimestepReplay);
});

it('accepts the first timestep when none has been recorded', function (): void {
    $attempt = mutableAttempt();
    $credential = totpCredential(timestep: null);

    expect(app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, 100),
    ))->toBe(TransitionOutcome::Succeeded);
});

it('applies several mutations for different targets in one transaction', function (): void {
    $attempt = mutableAttempt();
    $challenge = AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'password',
        'code_hash' => 'digest',
        'expires_at' => now()->addMinutes(2),
    ]);
    $credential = recoveryCredential();

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challenge->id, $attempt->id),
        new DisableCredential($credential->id),
    );

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and(AuthChallenge::findOrFail($challenge->id)->consumed_at)->not->toBeNull()
        ->and(AuthCredential::findOrFail($credential->id)->disabled_at)->not->toBeNull();
});

it('rolls every mutation back when one of them refuses', function (): void {
    $attempt = mutableAttempt();
    $challenge = AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'password',
        'code_hash' => 'digest',
        'expires_at' => now()->addMinutes(2),
    ]);
    $spent = recoveryCredential();
    $spent->update(['disabled_at' => now()]);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new ConsumeChallenge($challenge->id, $attempt->id),
        new DisableCredential($spent->id),
    );

    expect($outcome)->toBe(TransitionOutcome::CredentialAlreadyConsumed)
        ->and(AuthChallenge::findOrFail($challenge->id)->consumed_at)->toBeNull();
});

it('throws on two mutations sharing one target', function (): void {
    // A programming error, not a race. Applying both or arbitrarily picking one
    // would make the outcome depend on argument order.
    $attempt = mutableAttempt();
    $credential = totpCredential();

    app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new DisableCredential($credential->id),
        new AdvanceCredentialTimestep($credential->id, 101),
    );
})->throws(ConflictingMutations::class);

it('throws on a mutation type it cannot execute', function (): void {
    /*
     * PHP has no sealed interfaces, so a future driver can pass an
     * implementation the store has never heard of. Skipping it would silently
     * drop a single-use guard, which is the failure this whole design exists to
     * make impossible.
     */
    $attempt = mutableAttempt();

    $rogue = new class implements SingleUseMutation
    {
        public function target(): string
        {
            return 'rogue:1';
        }
    };

    app(AttemptStore::class)->transition($attempt, AttemptState::FactorSatisfied, $rogue);
})->throws(UnknownMutation::class);

it('writes nothing when an unknown mutation aborts the transaction', function (): void {
    $attempt = mutableAttempt();
    $credential = recoveryCredential();

    $rogue = new class implements SingleUseMutation
    {
        public function target(): string
        {
            return 'rogue:1';
        }
    };

    try {
        app(AttemptStore::class)->transition(
            $attempt,
            AttemptState::FactorSatisfied,
            new DisableCredential($credential->id),
            $rogue,
        );
    } catch (UnknownMutation) {
        // expected
    }

    expect(AuthCredential::findOrFail($credential->id)->disabled_at)->toBeNull()
        ->and(AuthAttempt::findOrFail($attempt->id)->version)->toBe(1);
});
```

- [ ] **Step 2: Run it and watch it fail**

Run: `vendor/bin/pest tests/Database/MutationStoreTest.php`
Expected: FAIL — the mutation namespace does not exist.

- [ ] **Step 3: Write the mutation interface and the three types**

`src/Attempts/Mutations/SingleUseMutation.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts\Mutations;

/**
 * A single-use state change that only the attempt store may execute.
 *
 * Typed value objects rather than driver-supplied SQL: the store knows how to
 * execute each one, so there is no injection surface and every single-use
 * mutation in the package is auditable in one place.
 */
interface SingleUseMutation
{
    /**
     * Stable conflict key, e.g. "credential:17" or "challenge:42".
     *
     * Two mutations sharing a target in one transition are a programming error.
     */
    public function target(): string;
}
```

`src/Attempts/Mutations/ConsumeChallenge.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts\Mutations;

/**
 * Burn a delivered challenge code.
 *
 * Carries the attempt id as well as the challenge id so the guarded update can
 * assert the challenge belongs to the attempt being advanced. Without it, a
 * challenge id leaked from another attempt would consume cleanly.
 */
final readonly class ConsumeChallenge implements SingleUseMutation
{
    public function __construct(
        public int $challengeId,
        public int $attemptId,
    ) {}

    public function target(): string
    {
        return 'challenge:' . $this->challengeId;
    }
}
```

`src/Attempts/Mutations/DisableCredential.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts\Mutations;

/**
 * Retire a credential permanently — a spent recovery code, in practice.
 */
final readonly class DisableCredential implements SingleUseMutation
{
    public function __construct(
        public int $credentialId,
    ) {}

    public function target(): string
    {
        return 'credential:' . $this->credentialId;
    }
}
```

`src/Attempts/Mutations/AdvanceCredentialTimestep.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts\Mutations;

/**
 * Move a TOTP credential's replay watermark forward.
 *
 * Shares the "credential:N" target namespace with DisableCredential
 * deliberately: applying both to one credential in a single transition is a
 * conflict worth refusing, not a combination worth supporting.
 */
final readonly class AdvanceCredentialTimestep implements SingleUseMutation
{
    public function __construct(
        public int $credentialId,
        public int $timestep,
    ) {}

    public function target(): string
    {
        return 'credential:' . $this->credentialId;
    }
}
```

- [ ] **Step 4: Write the two programming-error exceptions**

`src/Attempts/ConflictingMutations.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

use LogicException;

/**
 * Two single-use mutations named the same target in one transition.
 *
 * A LogicException rather than a TransitionOutcome: this is not a race a caller
 * can lose, it is a caller that built the request wrong. Silently applying both
 * or picking one would make the result depend on argument order.
 */
final class ConflictingMutations extends LogicException
{
    public static function forTarget(string $target): self
    {
        return new self(sprintf(
            'Two single-use mutations both target "%s" in one transition. Exactly one '
            . 'mutation may apply to a target per transition; applying both would make '
            . 'the outcome depend on argument order.',
            $target,
        ));
    }
}
```

`src/Attempts/UnknownMutation.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use LogicException;

/**
 * The store was handed a mutation type it cannot execute.
 *
 * PHP has no sealed interfaces, so a future driver can implement
 * SingleUseMutation with something the store has never seen. Skipping it would
 * silently drop a single-use guard — a spent recovery code left live, a replayed
 * timestep accepted — which is exactly the failure this design exists to
 * prevent. Throwing from inside the transaction aborts and rolls back.
 */
final class UnknownMutation extends LogicException
{
    public static function for(SingleUseMutation $mutation): self
    {
        return new self(sprintf(
            'DatabaseAttemptStore cannot execute %s (target "%s"). Every single-use '
            . 'mutation must be a type the store knows how to guard; add it there rather '
            . 'than writing the state from a driver.',
            $mutation::class,
            $mutation->target(),
        ));
    }
}
```

- [ ] **Step 5: Add the two new outcome cases**

In `src/Attempts/TransitionOutcome.php`, after the `ChallengeAlreadyConsumed` case:

```php
    /** The credential was already disabled — a recovery code spent, or replayed. */
    case CredentialAlreadyConsumed = 'credential_already_consumed';

    /** The TOTP timestep was already used, or the clock moved backwards. */
    case TimestepReplay = 'timestep_replay';
```

- [ ] **Step 6: Change the contract signature**

Replace the `transition` method in `src/Contracts/AttemptStore.php`:

```php
    /**
     * Attempt a state transition, applying any single-use mutations atomically
     * with it.
     *
     * All-or-nothing: if any mutation's guard has already fired, the attempt
     * does not advance; if the attempt's CAS loses, every mutation is rolled
     * back. A driver must never write single-use state itself — a code burned
     * outside this transaction stays burned when the transition then fails.
     *
     * @throws ConflictingMutations when two mutations share a target.
     * @throws UnknownMutation when a mutation type cannot be executed.
     */
    public function transition(
        AuthAttempt $attempt,
        AttemptState $to,
        SingleUseMutation ...$mutations,
    ): TransitionOutcome;
```

with the import `use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;` and the two exception imports for the `@throws` tags to resolve.

- [ ] **Step 7: Rewrite the store's transition method**

In `src/Attempts/DatabaseAttemptStore.php`, add the imports:

```php
use Fissible\Vouch\Attempts\Mutations\AdvanceCredentialTimestep;
use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Attempts\Mutations\DisableCredential;
use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use Illuminate\Database\Query\Builder as QueryBuilder;
```

Replace the signature and body, keeping the existing legality, context and CAS logic exactly as it is:

```php
    public function transition(
        AuthAttempt $attempt,
        AttemptState $to,
        SingleUseMutation ...$mutations,
    ): TransitionOutcome {
        // Legality is the kernel's decision, and costs no write.
        if (! $this->rules->allows($attempt->state, $to)) {
            return TransitionOutcome::IllegalTransition;
        }

        $stored = AuthAttempt::query()->find($attempt->id);

        if (! $stored instanceof AuthAttempt) {
            return TransitionOutcome::ConcurrentModification;
        }

        if ($stored->bound_context !== $attempt->bound_context) {
            return TransitionOutcome::ContextMismatch;
        }

        // Conflict detection is pure and costs no query, so it happens before
        // the transaction opens.
        $this->assertNoConflictingTargets($mutations);

        try {
            $this->connection->transaction(function () use ($attempt, $to, $mutations): void {
                foreach ($mutations as $mutation) {
                    $this->apply($mutation);
                }

                $advanced = $this->connection->table('auth_attempts')
                    ->where('id', $attempt->id)
                    ->where('version', $attempt->version)
                    ->where('expires_at', '>', $this->now())
                    ->update([
                        'state' => $to->value,
                        'version' => new Expression('version + 1'),
                        'updated_at' => $this->now(),
                    ]);

                if ($advanced !== 1) {
                    throw new TransitionRefused($this->expiredOrLostRace($attempt));
                }
            });
        } catch (TransitionRefused $refused) {
            return $refused->outcome;
        }

        return TransitionOutcome::Succeeded;
    }

    /**
     * @param list<SingleUseMutation> $mutations
     *
     * @throws ConflictingMutations
     */
    private function assertNoConflictingTargets(array $mutations): void
    {
        $seen = [];

        foreach ($mutations as $mutation) {
            $target = $mutation->target();

            if (isset($seen[$target])) {
                throw ConflictingMutations::forTarget($target);
            }

            $seen[$target] = true;
        }
    }

    /**
     * Execute one guarded update, requiring it to affect exactly one row.
     *
     * Zero rows means the guard already fired — consumed, replayed, or
     * concurrently taken — and refuses. More than one means the predicate was
     * wrong; every predicate here is keyed on a primary key, so it cannot
     * happen, and refusing rather than trusting it is the cheap direction.
     *
     * Type dispatch lives here and nowhere else. There is deliberately no
     * pre-flight type check duplicating this match: a second list of known types
     * is a second thing to forget to update.
     *
     * @throws UnknownMutation
     */
    private function apply(SingleUseMutation $mutation): void
    {
        $affected = match (true) {
            $mutation instanceof ConsumeChallenge => $this->connection->table('auth_challenges')
                ->where('id', $mutation->challengeId)
                ->where('attempt_id', $mutation->attemptId)
                ->whereNull('consumed_at')
                ->where('expires_at', '>', $this->now())
                ->update(['consumed_at' => $this->now()]),

            $mutation instanceof DisableCredential => $this->connection->table('auth_credentials')
                ->where('id', $mutation->credentialId)
                ->whereNull('disabled_at')
                ->update(['disabled_at' => $this->now(), 'updated_at' => $this->now()]),

            $mutation instanceof AdvanceCredentialTimestep => $this->connection->table('auth_credentials')
                ->where('id', $mutation->credentialId)
                ->where(static fn (QueryBuilder $query): QueryBuilder => $query
                    ->whereNull('last_used_timestep')
                    ->orWhere('last_used_timestep', '<', $mutation->timestep))
                ->update([
                    'last_used_timestep' => $mutation->timestep,
                    'last_used_at' => $this->now(),
                    'updated_at' => $this->now(),
                ]),

            default => throw UnknownMutation::for($mutation),
        };

        if ($affected !== 1) {
            throw new TransitionRefused(match (true) {
                $mutation instanceof ConsumeChallenge => TransitionOutcome::ChallengeAlreadyConsumed,
                $mutation instanceof DisableCredential => TransitionOutcome::CredentialAlreadyConsumed,
                default => TransitionOutcome::TimestepReplay,
            });
        }
    }
```

- [ ] **Step 8: Update the existing callers**

In `tests/Database/AttemptStoreTest.php` and `tests/Concurrency/AttemptStoreContentionTest.php`, replace every `transition($x, $state, $challenge->id)` with:

```php
transition($x, $state, new ConsumeChallenge($challenge->id, $attempt->id))
```

adding `use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;` to both files. In the contention test the attempt variable is `$attempt` in each case; use the id of the attempt that owns the challenge, not the stale copy.

- [ ] **Step 9: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Database/MutationStoreTest.php tests/Database/AttemptStoreTest.php`
Expected: PASS. 12 new tests plus the pre-existing store suite.

- [ ] **Step 10: Prove the rollback and the unknown-type refusal are load-bearing**

```bash
cp src/Attempts/DatabaseAttemptStore.php /tmp/das.bak
```

1. Change `default => throw UnknownMutation::for($mutation)` to `default => 1`. The two unknown-mutation tests must FAIL. This is the vacuous-control check that matters most here: `=> 1` is a plausible-looking "treat it as applied" that silently drops every guard the store does not recognise.
2. Move the `foreach ($mutations as $mutation)` loop to run *after* the attempt advance. The "rolls the credential disable back when the transition loses" test must still pass (the transaction covers both), but the "rolls every mutation back when one of them refuses" test must still pass too — if either goes green under a broken ordering, the assertion is not pinning atomicity.

Restore:

```bash
cp /tmp/das.bak src/Attempts/DatabaseAttemptStore.php
vendor/bin/pest tests/Database/MutationStoreTest.php   # green again
```

- [ ] **Step 11: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green. PHPStan will check that the `match (true)` arms narrow correctly; if it reports the `default` arm as unreachable, that is a real signal the arms are not exhaustive in the way intended — report it rather than suppressing.

- [ ] **Step 12: Commit**

```bash
git add src/Attempts src/Contracts/AttemptStore.php tests/Database/MutationStoreTest.php tests/Database/AttemptStoreTest.php tests/Concurrency/AttemptStoreContentionTest.php
git commit -m "feat!: the store owns every single-use mutation (Amendment C)

transition() takes variadic typed mutations instead of a nullable challenge
id. Type dispatch lives in exactly one match, with no pre-flight duplicate:
a second list of known types is a second thing to forget to update. An
unrecognised mutation throws from inside the transaction and rolls back,
rather than being skipped."
```

---

## Task 6: `EnrollmentGuard` — making `maxActiveCredentials()` an invariant

**Files:**
- Create: `src/Enrollment/EnrollmentGuard.php`, `src/Enrollment/EnrollmentRefused.php`, `src/Enrollment/EnrollmentRefusalReason.php`
- Modify: `config/vouch.php`, `tests/TestCase.php`
- Test: `tests/Database/EnrollmentGuardTest.php`

**Interfaces:**
- Consumes: `auth_enrollment_locks` from Task 2
- Produces:
  - `Fissible\Vouch\Enrollment\EnrollmentGuard::__construct(ConnectionInterface $connection, int $lockWaitSeconds)`
  - `EnrollmentGuard::serialize(int $userId, string $type, ?int $maxActive, callable $write): mixed`
  - `EnrollmentRefused extends RuntimeException` with `public readonly EnrollmentRefusalReason $reason`
  - `EnrollmentRefusalReason::CapacityExceeded`, `EnrollmentRefusalReason::Contended`
  - config keys `vouch.enrollment.lock_wait_seconds`

The cardinality check is a **post-condition**, not a pre-check. That is not a shortcut: password change and OTP re-enrollment both disable a row and create one inside the same closure, so a pre-check would refuse legitimate replacement while a post-check accepts it and still catches the double-enroll. One code path, and it is the stronger one.

- [ ] **Step 1: Add the config section and the SQLite test-harness settings**

In `config/vouch.php`, add before the closing `];`:

```php
    'enrollment' => [
        /*
         * How long a contended enrollment waits for the (user_id, type) lock
         * before refusing. Bounded on purpose: the engine defaults are wildly
         * inconsistent — MySQL waits 50s, Postgres waits forever, SQLite fails
         * immediately — and an unbounded wait hangs a request thread.
         */
        'lock_wait_seconds' => (int) env('VOUCH_ENROLLMENT_LOCK_WAIT', 5),
    ],
```

In `tests/TestCase.php`, the SQLite connection array needs two additions, because SQLite's default busy timeout is zero and a contending writer would fail instantly rather than waiting:

```php
            'sqlite' => $app['config']->set('database.connections.sqlite', [
                'driver' => 'sqlite',
                'database' => getenv('VOUCH_SQLITE_PATH') ?: ':memory:',
                'prefix' => '',
                'foreign_key_constraints' => true,
                // Contention tests need a writer to WAIT for the lock rather
                // than fail instantly. SQLite's default busy timeout is 0.
                'busy_timeout' => 5000,
                'journal_mode' => 'wal',
            ]),
```

- [ ] **Step 2: Write the failing test**

Create `tests/Database/EnrollmentGuardTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Enrollment\EnrollmentRefusalReason;
use Fissible\Vouch\Enrollment\EnrollmentRefused;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

function guard(): EnrollmentGuard
{
    return new EnrollmentGuard(DB::connection(), lockWaitSeconds: 5);
}

function makePassword(): AuthCredential
{
    return AuthCredential::create([
        'user_id' => 7,
        'type' => 'password',
        'secret' => 'digest',
        'strength' => 'knowledge',
    ]);
}

it('permits an enrollment within capacity and returns the write result', function (): void {
    $credential = guard()->serialize(7, 'password', 1, fn (): AuthCredential => makePassword());

    expect($credential)->toBeInstanceOf(AuthCredential::class)
        ->and(AuthCredential::where('user_id', 7)->count())->toBe(1);
});

it('claims the lock row on first use and reuses it afterwards', function (): void {
    guard()->serialize(7, 'password', null, fn (): bool => true);
    guard()->serialize(7, 'password', null, fn (): bool => true);

    expect(DB::table('auth_enrollment_locks')->where('user_id', 7)->count())->toBe(1);
});

it('refuses an enrollment that would exceed capacity, and writes nothing', function (): void {
    makePassword();

    try {
        guard()->serialize(7, 'password', 1, fn (): AuthCredential => makePassword());
        $this->fail('Expected EnrollmentRefused.');
    } catch (EnrollmentRefused $refused) {
        expect($refused->reason)->toBe(EnrollmentRefusalReason::CapacityExceeded);
    }

    expect(AuthCredential::where('user_id', 7)->count())->toBe(1);
});

it('permits replacement, which a pre-check would wrongly refuse', function (): void {
    /*
     * Password change and OTP re-enrollment both disable a row and create one
     * inside the same closure. Counting BEFORE the write would see 1 >= 1 and
     * refuse a legitimate operation; counting after sees the net result. This is
     * why the cardinality check is a post-condition.
     */
    $old = makePassword();

    $new = guard()->serialize(7, 'password', 1, function () use ($old): AuthCredential {
        $old->update(['disabled_at' => now()]);

        return makePassword();
    });

    expect($new->id)->not->toBe($old->id)
        ->and(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(1);
});

it('ignores disabled credentials when counting capacity', function (): void {
    // A revoked TOTP must never block enrolling its replacement. That would be a
    // self-inflicted lockout.
    makePassword()->update(['disabled_at' => now()]);

    guard()->serialize(7, 'password', 1, fn (): AuthCredential => makePassword());

    expect(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(1);
});

it('skips the capacity check entirely when the driver is unbounded', function (): void {
    foreach (range(1, 3) as $n) {
        guard()->serialize(7, 'email_otp', null, fn (): bool => true);
    }

    expect(true)->toBeTrue();
});

it('rolls the write back when the post-condition refuses', function (): void {
    // The closure creates two credentials where one is allowed. Both must vanish,
    // not just the second: a partially-applied enrollment is worse than none.
    try {
        guard()->serialize(7, 'password', 1, function (): void {
            makePassword();
            makePassword();
        });
        $this->fail('Expected EnrollmentRefused.');
    } catch (EnrollmentRefused) {
        // expected
    }

    expect(AuthCredential::where('user_id', 7)->count())->toBe(0);
});

it('does not disguise an unrelated database error as contention', function (): void {
    /*
     * A blanket QueryException -> Contended mapping would report a missing
     * table, a rejected session setting, or any future query defect as ordinary
     * enrollment contention. EnrollmentRefused::contended() tells the caller the
     * operation is safe to retry, which is exactly the wrong advice for a schema
     * problem — and on SQLite both failures carry the same SQLSTATE (HY000), so
     * nothing but the driver code separates them.
     */
    Schema::drop('auth_enrollment_locks');

    guard()->serialize(7, 'password', 1, fn (): bool => true);
})->throws(QueryException::class);

it('serializes per user and type rather than globally', function (): void {
    // Two users enrolling passwords must not contend with each other, and one
    // user's TOTP enrollment must not contend with their password enrollment.
    guard()->serialize(7, 'password', 1, fn (): AuthCredential => makePassword());
    guard()->serialize(7, 'totp', 1, fn (): AuthCredential => AuthCredential::create([
        'user_id' => 7, 'type' => 'totp', 'secret' => 'JBSWY3DPEHPK3PXP', 'strength' => 'possession',
    ]));

    expect(DB::table('auth_enrollment_locks')->count())->toBe(2);
});
```

- [ ] **Step 3: Run it and watch it fail**

Run: `vendor/bin/pest tests/Database/EnrollmentGuardTest.php`
Expected: FAIL — `EnrollmentGuard` not found.

- [ ] **Step 4: Write the refusal reason enum**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

/**
 * Why an enrollment was refused.
 *
 * Two cases rather than one because the engines genuinely diverge. On
 * MySQL and Postgres a loser blocks on the row lock, then observes the
 * committed count and refuses with CapacityExceeded. On SQLite — where
 * lockForUpdate() is a no-op and serialization comes from the database-level
 * write lock — the loser instead fails to acquire at all and refuses with
 * Contended. Both are clean refusals; a caller that cares can retry Contended.
 */
enum EnrollmentRefusalReason: string
{
    /** The write would leave more active credentials than the driver allows. */
    case CapacityExceeded = 'capacity_exceeded';

    /** Another enrollment for this (user, type) held the lock past the wait. */
    case Contended = 'contended';
}
```

- [ ] **Step 5: Write the exception**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

use RuntimeException;
use Throwable;

/**
 * An enrollment was refused, leaving nothing written.
 *
 * Typed rather than a raw QueryException: a contended lock surfaces as a driver
 * error on every engine — MySQL 1205, Postgres 55P03, SQLite 5 — and letting
 * that reach a caller would make "somebody else is enrolling right now"
 * indistinguishable from a database outage.
 */
final class EnrollmentRefused extends RuntimeException
{
    private function __construct(
        string $message,
        public readonly EnrollmentRefusalReason $reason,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function capacityExceeded(string $type, int $maxActive, int $actual): self
    {
        return new self(
            sprintf(
                'Enrolling this %s credential would leave %d active, but at most %d is allowed. '
                . 'Nothing was written. Disable the existing credential in the same operation if '
                . 'this was meant to replace it.',
                $type,
                $actual,
                $maxActive,
            ),
            EnrollmentRefusalReason::CapacityExceeded,
        );
    }

    public static function contended(string $type, Throwable $previous): self
    {
        return new self(
            sprintf(
                'Another enrollment for this user\'s %s credential is in progress and did not '
                . 'release in time. Nothing was written; this is safe to retry.',
                $type,
            ),
            EnrollmentRefusalReason::Contended,
            $previous,
        );
    }
}
```

- [ ] **Step 6: Write `EnrollmentGuard`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\QueryException;

/**
 * Serializes credential enrollment per (user_id, type) and enforces cardinality.
 *
 * maxActiveCredentials() is a property on a driver; it becomes an invariant only
 * when the write path is atomic. Count-then-insert is a read-modify-write, so
 * two concurrent enrollments each observe capacity and each proceed: two active
 * passwords, two TOTP secrets, or twenty recovery codes from two interleaved
 * regenerations.
 *
 * Row locks alone cannot fix it. SELECT ... FOR UPDATE over auth_credentials
 * locks the rows that exist, and the first-enrollment race is precisely the case
 * where there are none. Hence a dedicated lock row that always exists before the
 * count is taken.
 */
final class EnrollmentGuard
{
    public function __construct(
        private readonly ConnectionInterface $connection,
        private readonly int $lockWaitSeconds = 5,
    ) {}

    /**
     * Run $write with exclusive access to this user's credentials of this type,
     * refusing if the result would exceed $maxActive.
     *
     * The cardinality check is a POST-condition. A pre-check would refuse
     * password change and OTP re-enrollment, which disable a row and create one
     * inside the same closure; the post-check accepts those and still catches
     * the double-enroll. One code path, and it is the stronger one.
     *
     * @template TResult
     *
     * @param  int|null  $maxActive  Null means unbounded — skip the check entirely.
     * @param  callable(): TResult  $write
     * @return TResult
     *
     * @throws EnrollmentRefused
     */
    public function serialize(int $userId, string $type, ?int $maxActive, callable $write): mixed
    {
        return $this->connection->transaction(function () use ($userId, $type, $maxActive, $write): mixed {
            $this->acquire($userId, $type);

            $result = $write();

            if ($maxActive !== null) {
                $active = $this->countActive($userId, $type);

                if ($active > $maxActive) {
                    // Throwing rolls the whole closure back, so a partially
                    // applied enrollment cannot survive the refusal.
                    throw EnrollmentRefused::capacityExceeded($type, $maxActive, $active);
                }
            }

            return $result;
        });
    }

    /**
     * Claim and lock this subject's row.
     *
     * insertOrIgnore, NOT upsert with an empty update array: the latter compiles
     * to a plain INSERT on every engine and throws a unique violation the second
     * time. Verified on SQLite, MySQL 8 and Postgres 16.
     *
     * On MySQL and Postgres the lockForUpdate is what serializes. On SQLite it
     * compiles to a bare SELECT and does nothing — serialization there comes
     * from the database-level write lock that insertOrIgnore already took. Same
     * outcome, different mechanism; both are exercised by the contention matrix.
     *
     * @throws EnrollmentRefused
     */
    private function acquire(int $userId, string $type): void
    {
        try {
            $this->boundTheWait();

            $this->connection->table('auth_enrollment_locks')
                ->insertOrIgnore([['user_id' => $userId, 'type' => $type]]);

            $this->connection->table('auth_enrollment_locks')
                ->where('user_id', $userId)
                ->where('type', $type)
                ->lockForUpdate()
                ->first();
        } catch (QueryException $exception) {
            /*
             * ONLY verified lock/busy codes map to a refusal. A blanket
             * catch would report a dropped table, a rejected session setting, or
             * any future query defect as ordinary contention — and
             * EnrollmentRefused::contended() tells the caller it is "safe to
             * retry", which is precisely the wrong advice for a schema problem.
             * Everything else rethrows unchanged.
             */
            if (! $this->isLockContention($exception)) {
                throw $exception;
            }

            throw EnrollmentRefused::contended($type, $exception);
        }
    }

    /**
     * Is this exception a lock-wait timeout or a busy database?
     *
     * SQLSTATE alone cannot answer this. MySQL and SQLite both report contention
     * as HY000 — the general-error catch-all — and on SQLite a missing table is
     * ALSO HY000. So the driver-specific code is the discriminator on those two,
     * and the SQLSTATE is the discriminator on Postgres, which is the only engine
     * that gives contention its own.
     *
     * Measured against MySQL 8, Postgres 16 and SQLite:
     *
     *   contention     mysql HY000/1205   pgsql 55P03/7   sqlite HY000/5
     *   missing table  mysql 42S02/1146   pgsql 42P01/7   sqlite HY000/1
     *   bad column     mysql 42S22/1054   pgsql 42703/7   sqlite HY000/1
     *
     * Deadlock siblings — MySQL 1213, Postgres 40P01/40001, SQLite 6
     * (SQLITE_LOCKED) — are deliberately NOT matched. They are plausibly
     * retryable too, but they were not observed in the probe, and widening an
     * error mask on reasoning rather than measurement is the mistake this method
     * exists to correct. A deadlock therefore surfaces as a QueryException,
     * which is honest.
     *
     * An unrecognised driver returns false, so an unknown engine fails loudly
     * rather than silently classifying every error as contention.
     */
    private function isLockContention(QueryException $exception): bool
    {
        $driverCode = $exception->errorInfo[1] ?? null;

        return match ($this->connection->getDriverName()) {
            'mysql' => $driverCode === 1205,
            'pgsql' => $exception->getCode() === '55P03',
            'sqlite' => $driverCode === 5,
            default => false,
        };
    }

    /**
     * Bound the lock wait, because the engine defaults are wildly inconsistent:
     * MySQL waits 50 seconds, Postgres waits forever, SQLite fails immediately.
     * An unbounded wait hangs a request thread on a contended enrollment.
     */
    private function boundTheWait(): void
    {
        $seconds = max(1, $this->lockWaitSeconds);

        match ($this->connection->getDriverName()) {
            // SET LOCAL is scoped to this transaction and reverts on commit.
            'pgsql' => $this->connection->statement(sprintf("SET LOCAL lock_timeout = '%ds'", $seconds)),
            'mysql' => $this->connection->statement(sprintf('SET SESSION innodb_lock_wait_timeout = %d', $seconds)),
            'sqlite' => $this->connection->statement(sprintf('PRAGMA busy_timeout = %d', $seconds * 1000)),
            default => null,
        };
    }

    private function countActive(int $userId, string $type): int
    {
        return $this->connection->table('auth_credentials')
            ->where('user_id', $userId)
            ->where('type', $type)
            ->whereNull('disabled_at')
            ->count();
    }
}
```

- [ ] **Step 7: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Database/EnrollmentGuardTest.php`
Expected: PASS, 9 tests.

- [ ] **Step 8: Prove the post-condition is load-bearing**

```bash
cp src/Enrollment/EnrollmentGuard.php /tmp/eg.bak
```

Two probes.

1. Change `if ($active > $maxActive)` to `if ($active > $maxActive + 1)`. The capacity and rollback tests must FAIL.
2. Change `isLockContention()` to `return true;`. The "does not disguise an unrelated database error as contention" test must FAIL — it will see an `EnrollmentRefused` where a `QueryException` belongs. If it stays green, the classification is not being exercised and a dropped table would reach callers labelled "safe to retry."

Restore:

```bash
cp /tmp/eg.bak src/Enrollment/EnrollmentGuard.php
vendor/bin/pest tests/Database/EnrollmentGuardTest.php   # green again
```

The *contention* proof is deliberately not here — a single-connection test cannot demonstrate serialization. That is Task 12, and it is a completion gate rather than a follow-up.

- [ ] **Step 9: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 10: Commit**

```bash
git add src/Enrollment config/vouch.php tests/TestCase.php tests/Database/EnrollmentGuardTest.php
git commit -m "feat: serialize credential enrollment per (user_id, type)

insertOrIgnore rather than upsert-with-empty-update, which compiles to a
plain INSERT and throws on the second call. Cardinality is a post-condition,
not a pre-check: replacement disables and creates in one closure, which a
pre-check would refuse. Contention proof is Task 12."
```

---

## Task 7: The `Factor` contract and its value objects

**Files:**
- Create: `src/Contracts/Factor.php`, `src/Factors/ChallengeRequest.php`, `src/Factors/VerificationRequest.php`, `src/Factors/EnrollmentResult.php`, `src/Factors/FactorResult.php`, `src/Factors/FactorFailure.php`, `src/Factors/FactorRegistry.php`, `src/Factors/UnknownFactor.php`
- Modify: `tests/Pest.php`
- Test: `tests/Factors/FactorContractTest.php`

**Interfaces:**
- Consumes: `SingleUseMutation` from Task 5; `OneTimeSecret` from Task 1; the kernel's `SatisfiedFactor`, `FactorKind`, `FactorStrength`
- Produces: everything a driver task needs. Exact signatures are in the code blocks below; later tasks depend on them verbatim.

**One deliberate deviation from the spec.** Spec §2 lists `FactorFailure` as `NoCredential, Mismatch, Expired, Consumed, Malformed`. This adds a sixth case, `BindingMismatch`, because a code submitted from the wrong IP is a different fact from a wrong code, and the contract requires drivers to report **truthfully**. Collapsing the two would make the driver pre-decide that they are the same, which is a disclosure judgement and belongs to `ErrorShaper`. Flag this in the task report so the reviewer sees it as a choice rather than a slip.

- [ ] **Step 1: Register the new test directory with Testbench**

Driver tests need a database. In `tests/Pest.php`:

```php
uses(\Fissible\Vouch\Tests\TestCase::class)->in('Database', 'Concurrency', 'Factors');
```

- [ ] **Step 2: Write the failing contract test**

Create `tests/Factors/FactorContractTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\DisableCredential;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\UnknownFactor;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

function satisfiedFactor(string $id = 'password'): SatisfiedFactor
{
    return new SatisfiedFactor(
        factorId: $id,
        credentialId: '17',
        kind: FactorKind::Knowledge,
        strength: FactorStrength::Knowledge,
        isMultiFactor: false,
        userVerified: false,
        phishingResistant: false,
        authenticatorId: null,
        satisfiedAt: new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
    );
}

it('carries the satisfied factor and its mutations on success', function (): void {
    $result = FactorResult::satisfied(satisfiedFactor(), new DisableCredential(17));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->factor?->factorId)->toBe('password')
        ->and($result->mutations)->toHaveCount(1)
        ->and($result->failure)->toBeNull();
});

it('carries a truthful reason and no mutations on failure', function (): void {
    $result = FactorResult::failed(FactorFailure::Mismatch);

    expect($result->isSatisfied())->toBeFalse()
        ->and($result->failure)->toBe(FactorFailure::Mismatch)
        ->and($result->factor)->toBeNull()
        ->and($result->mutations)->toBe([]);
});

it('distinguishes a wrong code from a wrong request context', function (): void {
    /*
     * Deliberate extension to the spec's five-case list. A code submitted from
     * the wrong IP is a different fact from a wrong code, and drivers report
     * truthfully — deciding those are the same is a disclosure judgement, which
     * belongs to ErrorShaper and nowhere else.
     */
    expect(FactorFailure::BindingMismatch)->not->toBe(FactorFailure::Mismatch);
});

it('resolves a driver by its registry key', function (): void {
    $registry = new FactorRegistry();
    $registry->register(fakeFactor('totp'));

    expect($registry->get('totp')->id())->toBe('totp')
        ->and($registry->has('totp'))->toBeTrue()
        ->and($registry->has('passkey'))->toBeFalse();
});

it('refuses an unknown factor rather than returning null', function (): void {
    // Returning null would push the "is this a real factor?" decision to every
    // call site, and one of them will forget.
    (new FactorRegistry())->get('passkey');
})->throws(UnknownFactor::class);

it('refuses to register two drivers under one key', function (): void {
    // Silent replacement would let a host swap the recovery-code driver for a
    // permissive one by registering after vouch does.
    $registry = new FactorRegistry();
    $registry->register(fakeFactor('totp'));
    $registry->register(fakeFactor('totp'));
})->throws(LogicException::class);

function fakeFactor(string $id): Factor
{
    return new class($id) implements Factor
    {
        public function __construct(private readonly string $id) {}

        public function id(): string
        {
            return $this->id;
        }

        public function kind(): FactorKind
        {
            return FactorKind::Possession;
        }

        public function strength(): FactorStrength
        {
            return FactorStrength::Possession;
        }

        public function maxActiveCredentials(): ?int
        {
            return 1;
        }

        public function enroll(int $userId, array $data): \Fissible\Vouch\Factors\EnrollmentResult
        {
            return new \Fissible\Vouch\Factors\EnrollmentResult([]);
        }

        public function challenge(\Fissible\Vouch\Factors\ChallengeRequest $request): ?\Fissible\Vouch\Models\AuthChallenge
        {
            return null;
        }

        public function verify(\Fissible\Vouch\Factors\VerificationRequest $request): FactorResult
        {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        public function revoke(\Fissible\Vouch\Models\AuthCredential $credential): void {}
    };
}
```

- [ ] **Step 3: Run it and watch it fail**

Run: `vendor/bin/pest tests/Factors/FactorContractTest.php`
Expected: FAIL — `Fissible\Vouch\Contracts\Factor` not found.

- [ ] **Step 4: Write `FactorFailure`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

/**
 * Why a verification did not succeed — reported TRUTHFULLY and never pre-redacted.
 *
 * The kernel's ErrorShaper is the only response-facing boundary and decides
 * disclosure under the tenant's enumeration posture. A driver that self-censored
 * would make the strict-posture guarantee unverifiable, because two components
 * would each be deciding what a response may reveal and neither would own it.
 *
 * BindingMismatch extends the spec's five-case list deliberately: a code
 * submitted from the wrong IP is a different fact from a wrong code, and
 * deciding those are equivalent is a disclosure judgement.
 */
enum FactorFailure: string
{
    /** No usable credential of this type exists for the user. */
    case NoCredential = 'no_credential';

    /** The secret did not match. */
    case Mismatch = 'mismatch';

    /** The challenge or code is past its lifetime. */
    case Expired = 'expired';

    /** The challenge or code was already used. */
    case Consumed = 'consumed';

    /** The submitted input was the wrong shape to be a code at all. */
    case Malformed = 'malformed';

    /** The request context did not match what the challenge was bound to. */
    case BindingMismatch = 'binding_mismatch';
}
```

- [ ] **Step 5: Write `EnrollmentResult`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Secrets\OneTimeSecret;

/**
 * What an enrollment produced.
 *
 * Not a bare AuthCredential: recovery-code enrollment creates ten of them, and
 * both TOTP and recovery produce plaintext that is shown once and never
 * retrievable again.
 *
 * Secrets are OneTimeSecret rather than strings because a provisioning URI and
 * a recovery code are bearer material. The flow layer in 2.3 must reveal each
 * exactly once, straight into the response, and put it in no session, log,
 * audit event, or queued payload.
 */
final readonly class EnrollmentResult
{
    /**
     * @param  list<AuthCredential>  $credentials
     * @param  list<OneTimeSecret>  $secrets
     */
    public function __construct(
        public array $credentials,
        public array $secrets = [],
    ) {}
}
```

- [ ] **Step 6: Write `ChallengeRequest` and `VerificationRequest`**

`src/Factors/ChallengeRequest.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;

/**
 * Everything a driver needs to issue a challenge.
 *
 * The credential is optional because several valid flows do not know one at
 * challenge time: OTP is addressed via the attempt's identifier, recovery-code
 * verification selects the matching code only after input arrives, and passkey
 * assertion begins before the authenticator has chosen. Forcing drivers to
 * invent a credential to satisfy a signature would be a lie in the type system.
 *
 * Client IP and user agent travel here because auth_challenges binds them and
 * the attempt carries only bound_context, which is the session.
 */
final readonly class ChallengeRequest
{
    public function __construct(
        public AuthAttempt $attempt,
        public ?AuthCredential $credential = null,
        public ?string $clientIp = null,
        public ?string $clientUserAgent = null,
    ) {}
}
```

`src/Factors/VerificationRequest.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;

/**
 * Everything a driver needs to verify a submission.
 *
 * The IP and user agent are not optional decoration. The challenge records
 * bound_ip and bound_user_agent at delivery, and a driver with no request
 * context cannot compare them — so the binding would be written to the database
 * and never checked. A guard that is stored but never evaluated is not a guard.
 *
 * $input stays an untyped array in v1: enrollment and verification payloads are
 * genuinely heterogeneous across drivers, and each validates its own at entry.
 * Typed DTOs are recorded as a follow-up in spec §7.
 */
final readonly class VerificationRequest
{
    /**
     * @param  array<string, mixed>  $input
     */
    public function __construct(
        public AuthAttempt $attempt,
        public array $input,
        public ?AuthCredential $credential = null,
        public ?AuthChallenge $challenge = null,
        public ?string $clientIp = null,
        public ?string $clientUserAgent = null,
    ) {}

    /**
     * Read a string field, or null when it is absent or the wrong type.
     *
     * Drivers must not trust $input's shape: it arrives from a request body.
     */
    public function string(string $key): ?string
    {
        $value = $this->input[$key] ?? null;

        return is_string($value) ? $value : null;
    }
}
```

- [ ] **Step 7: Write `FactorResult`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

/**
 * The outcome of a verification, plus any single-use state the store must write.
 *
 * This is the seam between Phase 2 and Phase 1. The driver is the only component
 * that knows whether user verification actually occurred, whether its mechanism
 * is phishing-resistant, and which credential was used; it reports those
 * honestly and hands them over. The kernel decides satisfiability.
 *
 * Drivers never evaluate policy, and they never write the mutations they return.
 */
final readonly class FactorResult
{
    /**
     * @param  list<SingleUseMutation>  $mutations
     */
    private function __construct(
        public ?SatisfiedFactor $factor,
        public ?FactorFailure $failure,
        public array $mutations,
    ) {}

    public static function satisfied(SatisfiedFactor $factor, SingleUseMutation ...$mutations): self
    {
        return new self($factor, null, array_values($mutations));
    }

    public static function failed(FactorFailure $reason): self
    {
        return new self(null, $reason, []);
    }

    /**
     * @phpstan-assert-if-true !null $this->factor
     * @phpstan-assert-if-false !null $this->failure
     */
    public function isSatisfied(): bool
    {
        return $this->factor !== null;
    }
}
```

- [ ] **Step 8: Write the `Factor` contract**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;

/**
 * One authentication factor: how it enrolls, challenges, and verifies.
 *
 * Two rules bind every implementation:
 *
 *  - **Drivers validate; they never evaluate policy.** Report what happened and
 *    let the kernel judge satisfiability.
 *  - **Drivers never write single-use state.** Return SingleUseMutation objects
 *    on the FactorResult and let the store execute them inside its transaction.
 *    A code burned outside that transaction stays burned when the transition
 *    then fails, which is a denial of service against a legitimate user.
 *
 * Takes `int $userId` rather than a user model: vouch never references the
 * host's authenticatable class, and every foreign key in the schema is a plain
 * integer.
 */
interface Factor
{
    /** Registry key. Matches auth_credentials.type. */
    public function id(): string;

    public function kind(): FactorKind;

    public function strength(): FactorStrength;

    /**
     * 1, a finite number, or null for unbounded.
     *
     * Counted over ACTIVE credentials only — disabled_at IS NULL. A revoked TOTP
     * must never block enrolling its replacement; that would be a self-inflicted
     * lockout. Enforcement is EnrollmentGuard's, not the driver's: a property is
     * not an invariant until the write path is atomic.
     */
    public function maxActiveCredentials(): ?int;

    /**
     * @param  array<string, mixed>  $data
     */
    public function enroll(int $userId, array $data): EnrollmentResult;

    /** Null when the factor needs no challenge — password, TOTP, recovery code. */
    public function challenge(ChallengeRequest $request): ?AuthChallenge;

    public function verify(VerificationRequest $request): FactorResult;

    public function revoke(AuthCredential $credential): void;
}
```

- [ ] **Step 9: Write `UnknownFactor` and `FactorRegistry`**

`src/Factors/UnknownFactor.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use InvalidArgumentException;

final class UnknownFactor extends InvalidArgumentException
{
    /**
     * @param  list<string>  $known
     */
    public static function for(string $id, array $known): self
    {
        return new self(sprintf(
            'No factor driver is registered for "%s". Registered: %s.',
            $id,
            $known === [] ? 'none' : implode(', ', $known),
        ));
    }
}
```

`src/Factors/FactorRegistry.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Contracts\Factor;
use LogicException;

/**
 * Resolves an auth_credentials.type to the driver that owns it.
 *
 * Registration is write-once. Silent replacement would let a host swap the
 * recovery-code driver — the one carrying FactorStrength::Recovery, which is
 * what keeps a recovery code from satisfying a policy — for a permissive one,
 * simply by registering after vouch does.
 */
final class FactorRegistry
{
    /** @var array<string, Factor> */
    private array $factors = [];

    public function register(Factor $factor): void
    {
        $id = $factor->id();

        if (isset($this->factors[$id])) {
            throw new LogicException(sprintf(
                'A factor driver is already registered for "%s" (%s). Registration is '
                . 'write-once: replacing a driver silently would let a permissive '
                . 'implementation displace a restrictive one.',
                $id,
                $this->factors[$id]::class,
            ));
        }

        $this->factors[$id] = $factor;
    }

    public function has(string $id): bool
    {
        return isset($this->factors[$id]);
    }

    /**
     * @throws UnknownFactor
     */
    public function get(string $id): Factor
    {
        return $this->factors[$id] ?? throw UnknownFactor::for($id, array_keys($this->factors));
    }

    /**
     * @return list<Factor>
     */
    public function all(): array
    {
        return array_values($this->factors);
    }
}
```

- [ ] **Step 10: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Factors/FactorContractTest.php`
Expected: PASS, 6 tests.

- [ ] **Step 11: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green. PHPStan level 9 will check the `@phpstan-assert-if-true` annotations on `isSatisfied()`; if it disagrees, fix the annotation rather than removing it — later tasks rely on that narrowing.

- [ ] **Step 12: Commit**

```bash
git add src/Contracts/Factor.php src/Factors tests/Factors tests/Pest.php
git commit -m "feat: add the Factor contract and its value objects

VerificationRequest carries client IP and user agent, without which
bound_ip/bound_user_agent would be stored and never compared. FactorFailure
adds a sixth case, BindingMismatch, beyond the spec's five: a wrong request
context is a different fact from a wrong code, and collapsing them is a
disclosure judgement that belongs to ErrorShaper."
```

---

## Task 8: The password and recovery-code drivers

**Files:**
- Create: `src/Factors/Drivers/PasswordFactor.php`, `src/Factors/Drivers/RecoveryCodeFactor.php`
- Modify: `config/vouch.php`
- Test: `tests/Factors/PasswordFactorTest.php`, `tests/Factors/RecoveryCodeFactorTest.php`

**Interfaces:**
- Consumes: `Factor`, `EnrollmentResult`, `FactorResult`, `FactorFailure`, `VerificationRequest`, `ChallengeRequest` from Task 7; `EnrollmentGuard` from Task 6; `DisableCredential` from Task 5; `OneTimeSecret` from Task 1
- Produces:
  - `PasswordFactor::__construct(EnrollmentGuard $guard, ClockInterface $clock)` — `id()` returns `'password'`
  - `RecoveryCodeFactor::__construct(EnrollmentGuard $guard, ClockInterface $clock, int $count, int $length)` — `id()` returns `'recovery_code'`
  - config keys `vouch.recovery.count`, `vouch.recovery.length`

Both hash with the host-configured `Hash` driver and neither issues a challenge, so they share a task. Recovery is the one that matters: it is the only driver in 2.2 returning a `SingleUseMutation`, and the only one carrying `FactorStrength::Recovery`.

- [ ] **Step 1: Add the config section**

In `config/vouch.php`, add before the closing `];`:

```php
    'recovery' => [
        // Regeneration replaces the whole set, so this is the size of a set.
        'count' => (int) env('VOUCH_RECOVERY_CODE_COUNT', 10),

        /*
         * Characters per code, drawn from a 32-symbol alphabet, so 10 characters
         * is 50 bits of entropy. Codes are generated with random_int(), a CSPRNG;
         * rand() and mt_rand() are predictable from observed output and must
         * never appear on this path.
         */
        'length' => (int) env('VOUCH_RECOVERY_CODE_LENGTH', 10),
    ],
```

- [ ] **Step 2: Write the failing password test**

Create `tests/Factors/PasswordFactorTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentRefused;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function passwordFactor(): PasswordFactor
{
    return app(PasswordFactor::class);
}

function driverAttempt(?int $userId = 7): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => $userId,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ]);
}

it('describes itself as a single knowledge factor', function (): void {
    $factor = passwordFactor();

    expect($factor->id())->toBe('password')
        ->and($factor->kind())->toBe(FactorKind::Knowledge)
        ->and($factor->strength())->toBe(FactorStrength::Knowledge)
        ->and($factor->maxActiveCredentials())->toBe(1);
});

it('stores a digest and never the password', function (): void {
    $result = passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);

    $credential = $result->credentials[0];

    expect($result->credentials)->toHaveCount(1)
        ->and($result->secrets)->toBe([])
        ->and($credential->secret)->not->toBe('correct horse battery staple')
        ->and(password_get_info((string) $credential->secret)['algo'])->not->toBeNull();
});

it('issues no challenge', function (): void {
    expect(passwordFactor()->challenge(new ChallengeRequest(driverAttempt())))->toBeNull();
});

it('satisfies with the correct password and writes no single-use state', function (): void {
    // Password is not single-use. A driver returning a mutation here would be
    // writing on the verification path for no reason.
    passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);

    $result = passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => 'correct horse battery staple'],
    ));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->mutations)->toBe([])
        ->and($result->factor?->strength)->toBe(FactorStrength::Knowledge)
        ->and($result->factor?->isMultiFactor)->toBeFalse()
        ->and($result->factor?->userVerified)->toBeFalse()
        ->and($result->factor?->phishingResistant)->toBeFalse();
});

it('reports a mismatch truthfully rather than pre-redacting it', function (): void {
    passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);

    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => 'wrong'],
    ))->failure)->toBe(FactorFailure::Mismatch);
});

it('distinguishes no credential from a wrong password', function (): void {
    // ErrorShaper collapses these under a strict posture. The driver must not,
    // or the strict-posture guarantee becomes unverifiable.
    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => 'anything'],
    ))->failure)->toBe(FactorFailure::NoCredential);
});

it('reports malformed input rather than treating it as a wrong password', function (): void {
    passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);

    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => ['array', 'not', 'string']],
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('refuses to verify against a disabled credential', function (): void {
    passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);
    AuthCredential::where('user_id', 7)->update(['disabled_at' => now()]);

    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => 'correct horse battery staple'],
    ))->failure)->toBe(FactorFailure::NoCredential);
});

it('refuses a second password rather than leaving two live', function (): void {
    passwordFactor()->enroll(7, ['password' => 'first']);
    passwordFactor()->enroll(7, ['password' => 'second']);
})->throws(EnrollmentRefused::class);

it('replaces a password in one operation', function (): void {
    passwordFactor()->enroll(7, ['password' => 'first']);
    passwordFactor()->enroll(7, ['password' => 'second', 'replace' => true]);

    expect(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(1)
        ->and(passwordFactor()->verify(new VerificationRequest(
            attempt: driverAttempt(),
            input: ['password' => 'second'],
        ))->isSatisfied())->toBeTrue();
});

it('cannot verify against an attempt with no identified user', function (): void {
    passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);

    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(userId: null),
        input: ['password' => 'correct horse battery staple'],
    ))->failure)->toBe(FactorFailure::NoCredential);
});
```

- [ ] **Step 3: Run it and watch it fail**

Run: `vendor/bin/pest tests/Factors/PasswordFactorTest.php`
Expected: FAIL — `PasswordFactor` not found.

- [ ] **Step 4: Write `PasswordFactor`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Support\Facades\Hash;
use Psr\Clock\ClockInterface;

/**
 * The knowledge factor.
 *
 * Rehash-on-verify is deliberately absent in v1, and that is a
 * SECURITY-MAINTENANCE LIMITATION rather than a deferred optimisation: raising
 * the bcrypt cost, or moving to a stronger algorithm, reaches new and changed
 * passwords only. A user who never changes theirs keeps the hash they enrolled
 * with indefinitely. It was left out because it is a credential write on the
 * verification path, and threading it through the single-use mutation machinery
 * would blur a boundary in the slice that establishes it. Any operator raising
 * the work factor needs to know it will not propagate.
 */
final readonly class PasswordFactor implements Factor
{
    public function __construct(
        private EnrollmentGuard $guard,
        private ClockInterface $clock,
    ) {}

    public function id(): string
    {
        return 'password';
    }

    public function kind(): FactorKind
    {
        return FactorKind::Knowledge;
    }

    public function strength(): FactorStrength
    {
        return FactorStrength::Knowledge;
    }

    public function maxActiveCredentials(): ?int
    {
        return 1;
    }

    /**
     * @param  array{password?: mixed, replace?: mixed}  $data
     */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        $password = $data['password'] ?? null;

        if (! is_string($password) || $password === '') {
            throw new \InvalidArgumentException('PasswordFactor::enroll() requires a non-empty "password" string.');
        }

        $replace = ($data['replace'] ?? false) === true;

        $credential = $this->guard->serialize(
            $userId,
            $this->id(),
            $this->maxActiveCredentials(),
            function () use ($userId, $password, $replace): AuthCredential {
                if ($replace) {
                    /*
                     * Disable and create inside ONE serialized closure, so the
                     * guard's post-condition sees the net result. This is why
                     * cardinality is checked after the write rather than before.
                     */
                    AuthCredential::query()
                        ->where('user_id', $userId)
                        ->where('type', $this->id())
                        ->whereNull('disabled_at')
                        ->update(['disabled_at' => $this->clock->now()]);
                }

                return AuthCredential::create([
                    'user_id' => $userId,
                    'type' => $this->id(),
                    'secret' => Hash::make($password),
                    'strength' => $this->strength()->name,
                ]);
            },
        );

        // No one-time secrets: the user already knows their password.
        return new EnrollmentResult([$credential]);
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        return null;
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        $submitted = $request->string('password');

        if ($submitted === null) {
            return FactorResult::failed(FactorFailure::Malformed);
        }

        $userId = $request->attempt->user_id;

        if ($userId === null) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        $credential = AuthCredential::query()
            ->where('user_id', $userId)
            ->where('type', $this->id())
            ->whereNull('disabled_at')
            ->first();

        if (! $credential instanceof AuthCredential || ! is_string($credential->secret)) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        if (! Hash::check($submitted, $credential->secret)) {
            return FactorResult::failed(FactorFailure::Mismatch);
        }

        /*
         * No mutations. A password is not single-use, and returning one here
         * would put a write on the verification path for no security reason.
         */
        return FactorResult::satisfied(new SatisfiedFactor(
            factorId: $this->id(),
            credentialId: (string) $credential->id,
            kind: $this->kind(),
            strength: $this->strength(),
            isMultiFactor: false,
            userVerified: false,
            phishingResistant: false,
            authenticatorId: null,
            satisfiedAt: $this->clock->now(),
        ));
    }

    public function revoke(AuthCredential $credential): void
    {
        $credential->update(['disabled_at' => $this->clock->now()]);
    }
}
```

- [ ] **Step 5: Register the driver so `app(PasswordFactor::class)` resolves**

In `src/VouchServiceProvider.php`'s `register()`, add:

```php
        $this->app->singleton(
            \Fissible\Vouch\Enrollment\EnrollmentGuard::class,
            fn ($app): \Fissible\Vouch\Enrollment\EnrollmentGuard => new \Fissible\Vouch\Enrollment\EnrollmentGuard(
                $app['db']->connection(),
                (int) config('vouch.enrollment.lock_wait_seconds'),
            ),
        );

        $this->app->singleton(
            \Psr\Clock\ClockInterface::class,
            \Fissible\Vouch\Support\SystemClock::class,
        );
```

Task 11 adds the registry and the remaining drivers; this is the minimum for the password tests to resolve.

- [ ] **Step 6: Run the password tests and watch them pass**

Run: `vendor/bin/pest tests/Factors/PasswordFactorTest.php`
Expected: PASS, 11 tests.

- [ ] **Step 7: Write the failing recovery-code test**

Create `tests/Factors/RecoveryCodeFactorTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\DisableCredential;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Policy\PolicyParser;
use Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function recoveryFactor(): RecoveryCodeFactor
{
    return app(RecoveryCodeFactor::class);
}

function recoveryAttempt(?int $userId = 7): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => $userId,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ]);
}

/** @return list<string> */
function enrollRecoveryCodes(int $userId = 7): array
{
    $result = recoveryFactor()->enroll($userId, []);

    return array_map(static fn ($secret): string => $secret->reveal(), $result->secrets);
}

it('carries recovery strength, which is what excludes it from policy', function (): void {
    expect(recoveryFactor()->strength())->toBe(FactorStrength::Recovery)
        ->and(recoveryFactor()->maxActiveCredentials())->toBe(10);
});

it('creates ten credentials and returns ten one-time secrets', function (): void {
    $result = recoveryFactor()->enroll(7, []);

    expect($result->credentials)->toHaveCount(10)
        ->and($result->secrets)->toHaveCount(10);
});

it('never stores a code in plaintext', function (): void {
    $codes = enrollRecoveryCodes();

    $stored = AuthCredential::where('user_id', 7)->pluck('secret')->all();

    foreach ($codes as $code) {
        expect($stored)->not->toContain($code);
    }
});

it('issues distinct codes', function (): void {
    $codes = enrollRecoveryCodes();

    expect(array_unique($codes))->toHaveCount(10);
});

it('satisfies with a valid code and returns exactly one disable mutation', function (): void {
    $codes = enrollRecoveryCodes();

    $result = recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => $codes[3]],
    ));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->mutations)->toHaveCount(1)
        ->and($result->mutations[0])->toBeInstanceOf(DisableCredential::class);
});

it('does not itself burn the code it matched', function (): void {
    /*
     * The whole reason single-use state belongs to the store. If the driver
     * disabled the credential here, a subsequent failed transition would leave
     * the code spent and the user unauthenticated.
     */
    $codes = enrollRecoveryCodes();

    recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => $codes[0]],
    ));

    expect(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(10);
});

it('burns the code only when the store commits the transition', function (): void {
    $codes = enrollRecoveryCodes();
    $attempt = recoveryAttempt();

    $result = recoveryFactor()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $codes[0]],
    ));

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        ...$result->mutations,
    );

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(9);
});

it('refuses a code that has already been spent', function (): void {
    $codes = enrollRecoveryCodes();
    $attempt = recoveryAttempt();

    $first = recoveryFactor()->verify(new VerificationRequest($attempt, ['code' => $codes[0]]));
    app(AttemptStore::class)->transition($attempt, AttemptState::FactorSatisfied, ...$first->mutations);

    expect(recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => $codes[0]],
    ))->failure)->toBe(FactorFailure::Mismatch);
});

it('regenerating invalidates every prior code', function (): void {
    $old = enrollRecoveryCodes();
    $new = enrollRecoveryCodes();

    expect(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(10)
        ->and(recoveryFactor()->verify(new VerificationRequest(
            attempt: recoveryAttempt(),
            input: ['code' => $old[0]],
        ))->failure)->toBe(FactorFailure::Mismatch)
        ->and(recoveryFactor()->verify(new VerificationRequest(
            attempt: recoveryAttempt(),
            input: ['code' => $new[0]],
        ))->isSatisfied())->toBeTrue();
});

it('cannot satisfy a policy, asserted through the kernel rather than the driver', function (): void {
    /*
     * The guard lives in SatisfiabilityEvaluator, which filters Recovery
     * explicitly rather than relying on strength ordering. Asserting it here
     * through the evaluator — not by reading the driver's own metadata — is what
     * makes this test worth having: a driver that lied about its strength would
     * still be caught by the evaluator, and this proves the evaluator is what
     * decides.
     */
    $codes = enrollRecoveryCodes();

    $result = recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => $codes[0]],
    ));

    $policy = (new PolicyParser())->parse(['any_of' => ['recovery_code', 'password']]);
    $verdict = (new SatisfiabilityEvaluator())->evaluate($policy, [$result->factor]);

    // Verdict exposes a public `satisfied` property, not a method.
    expect($verdict->satisfied)->toBeFalse();
});

it('reports malformed input rather than a mismatch', function (): void {
    enrollRecoveryCodes();

    expect(recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: [],
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('reports no credential when the user has never enrolled', function (): void {
    expect(recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => 'ABCDEFGHJK'],
    ))->failure)->toBe(FactorFailure::NoCredential);
});
```

Note: `SatisfiabilityEvaluator::evaluate(Requirement $requirement, array $satisfied): Verdict`, and `Verdict` is a readonly value object with public `bool $satisfied` and `list<SatisfiedFactor> $usedFactors`. Do not add an accessor to the kernel to suit a test.

- [ ] **Step 8: Run it and watch it fail**

Run: `vendor/bin/pest tests/Factors/RecoveryCodeFactorTest.php`
Expected: FAIL — `RecoveryCodeFactor` not found.

- [ ] **Step 9: Write `RecoveryCodeFactor`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

use Fissible\Vouch\Attempts\Mutations\DisableCredential;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Secrets\OneTimeSecret;
use Illuminate\Support\Facades\Hash;
use Psr\Clock\ClockInterface;

/**
 * Single-use recovery codes: one credential row per code.
 *
 * Carries FactorStrength::Recovery, which SatisfiabilityEvaluator filters out of
 * both satisfiability and assurance facts. A recovery code therefore cannot
 * satisfy a policy BY CONSTRUCTION rather than by driver discipline — the guard
 * lives in kernel code that is mutation-tested.
 *
 * Verification compares against every active code in turn, which is up to ten
 * hash comparisons per attempt. That is a real cost and a real amplification
 * factor; rate limiting is 2.3's, and this driver deliberately does not invent
 * its own.
 */
final readonly class RecoveryCodeFactor implements Factor
{
    /** Crockford-style alphabet: no I, L, O, U, so a transcribed code is unambiguous. */
    private const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    public function __construct(
        private EnrollmentGuard $guard,
        private ClockInterface $clock,
        private int $count = 10,
        private int $length = 10,
    ) {}

    public function id(): string
    {
        return 'recovery_code';
    }

    public function kind(): FactorKind
    {
        return FactorKind::Possession;
    }

    public function strength(): FactorStrength
    {
        return FactorStrength::Recovery;
    }

    public function maxActiveCredentials(): ?int
    {
        return $this->count;
    }

    /**
     * Generate a fresh set, retiring every prior code.
     *
     * Enrollment and regeneration are the same operation: disabling first makes
     * it idempotent whether or not codes already exist, and satisfies the
     * promise that regenerating invalidates all prior codes. Both halves run
     * inside one serialized closure, so a concurrent pair cannot interleave into
     * a mixed set.
     *
     * @param  array<string, mixed>  $data
     */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        /** @var array{codes: list<string>, credentials: list<AuthCredential>} $generated */
        $generated = $this->guard->serialize(
            $userId,
            $this->id(),
            $this->maxActiveCredentials(),
            function () use ($userId): array {
                AuthCredential::query()
                    ->where('user_id', $userId)
                    ->where('type', $this->id())
                    ->whereNull('disabled_at')
                    ->update(['disabled_at' => $this->clock->now()]);

                $codes = [];
                $credentials = [];

                for ($i = 0; $i < $this->count; $i++) {
                    $code = $this->generateCode();
                    $codes[] = $code;
                    $credentials[] = AuthCredential::create([
                        'user_id' => $userId,
                        'type' => $this->id(),
                        'secret' => Hash::make($code),
                        'strength' => $this->strength()->name,
                    ]);
                }

                return ['codes' => $codes, 'credentials' => $credentials];
            },
        );

        return new EnrollmentResult(
            $generated['credentials'],
            array_map(static fn (string $code): OneTimeSecret => new OneTimeSecret($code), $generated['codes']),
        );
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        return null;
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        $submitted = $request->string('code');

        if ($submitted === null) {
            return FactorResult::failed(FactorFailure::Malformed);
        }

        $userId = $request->attempt->user_id;

        if ($userId === null) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        $candidates = AuthCredential::query()
            ->where('user_id', $userId)
            ->where('type', $this->id())
            ->whereNull('disabled_at')
            ->get();

        if ($candidates->isEmpty()) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        $normalised = strtoupper(str_replace([' ', '-'], '', $submitted));

        foreach ($candidates as $credential) {
            if (! is_string($credential->secret) || ! Hash::check($normalised, $credential->secret)) {
                continue;
            }

            /*
             * Return the mutation; do NOT disable here. A code burned by the
             * driver stays burned when the transition then fails, which is a
             * denial of service against a legitimate user.
             */
            return FactorResult::satisfied(
                new SatisfiedFactor(
                    factorId: $this->id(),
                    credentialId: (string) $credential->id,
                    kind: $this->kind(),
                    strength: $this->strength(),
                    isMultiFactor: false,
                    userVerified: false,
                    phishingResistant: false,
                    authenticatorId: null,
                    satisfiedAt: $this->clock->now(),
                ),
                new DisableCredential($credential->id),
            );
        }

        return FactorResult::failed(FactorFailure::Mismatch);
    }

    public function revoke(AuthCredential $credential): void
    {
        $credential->update(['disabled_at' => $this->clock->now()]);
    }

    /**
     * random_int() is a CSPRNG. rand() and mt_rand() are predictable from
     * observed output, and a predictable recovery code is a bypass of every
     * other factor on the account.
     */
    private function generateCode(): string
    {
        $alphabet = self::ALPHABET;
        $max = strlen($alphabet) - 1;
        $code = '';

        for ($i = 0; $i < $this->length; $i++) {
            $code .= $alphabet[random_int(0, $max)];
        }

        return $code;
    }
}
```

- [ ] **Step 10: Bind the recovery driver's constructor arguments**

In `src/VouchServiceProvider.php`'s `register()`:

```php
        $this->app->singleton(
            \Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class,
            fn ($app): \Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor => new \Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor(
                $app->make(\Fissible\Vouch\Enrollment\EnrollmentGuard::class),
                $app->make(\Psr\Clock\ClockInterface::class),
                (int) config('vouch.recovery.count'),
                (int) config('vouch.recovery.length'),
            ),
        );
```

- [ ] **Step 11: Run the recovery tests and watch them pass**

Run: `vendor/bin/pest tests/Factors/RecoveryCodeFactorTest.php`
Expected: PASS, 12 tests.

- [ ] **Step 12: Prove the store-owns-the-burn design is load-bearing**

```bash
cp src/Factors/Drivers/RecoveryCodeFactor.php /tmp/rcf.bak
```

Make the driver disable the credential itself, immediately before returning `FactorResult::satisfied(...)`. The "does not itself burn the code it matched" test must FAIL. This is the single most important non-vacuity check in this task: it is the difference between a design that survives a failed transition and one that silently denies service. Restore:

```bash
cp /tmp/rcf.bak src/Factors/Drivers/RecoveryCodeFactor.php
vendor/bin/pest tests/Factors/RecoveryCodeFactorTest.php   # green again
```

- [ ] **Step 13: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 14: Commit**

```bash
git add src/Factors/Drivers/PasswordFactor.php src/Factors/Drivers/RecoveryCodeFactor.php src/VouchServiceProvider.php config/vouch.php tests/Factors/PasswordFactorTest.php tests/Factors/RecoveryCodeFactorTest.php
git commit -m "feat: add the password and recovery-code drivers

Recovery verification returns a DisableCredential mutation rather than
burning the code itself: a code burned by the driver stays burned when the
transition then fails. Its exclusion from policy is asserted through
SatisfiabilityEvaluator, not by reading the driver's own metadata."
```

---

## Task 9: The TOTP driver

**Files:**
- Create: `src/Factors/Drivers/TotpFactor.php`
- Modify: `config/vouch.php`, `src/VouchServiceProvider.php`
- Test: `tests/Factors/TotpFactorTest.php`

**Interfaces:**
- Consumes: `AdvanceCredentialTimestep` from Task 5; `EnrollmentGuard` from Task 6; the Task 7 value objects; `auth_credentials.last_used_timestep` from Task 2
- Produces: `TotpFactor::__construct(EnrollmentGuard $guard, ClockInterface $clock, string $issuer, int $period, int $digits, int $window)` — `id()` returns `'totp'`; config keys `vouch.totp.issuer`, `vouch.totp.period`, `vouch.totp.digits`, `vouch.totp.window`

**The critical constraint, verified against otphp 11.5.0's source.** `TOTP::verify($otp, $timestamp, $leeway)` returns **`bool` only** — it does not report which timestep matched. Amendment B needs the matched timestep to record it. Therefore:

> **Never pass a non-null `$leeway` to `verify()` in this driver.** Iterate candidate timesteps yourself and call `verify($code, $step * $period, null)` for each. That form compares exactly at the given timestamp, so a match identifies the timestep unambiguously.

Using the leeway parameter would make the driver look correct while leaving `last_used_timestep` unknowable — the exact shape of failure Amendment B exists to prevent.

- [ ] **Step 1: Add the config section**

In `config/vouch.php`, add before the closing `];`:

```php
    'totp' => [
        // Shown in the authenticator app next to the account label.
        'issuer' => env('VOUCH_TOTP_ISSUER', 'Vouch'),

        // RFC 6238 defaults. Changing period or digits invalidates enrolled secrets.
        'period' => (int) env('VOUCH_TOTP_PERIOD', 30),
        'digits' => (int) env('VOUCH_TOTP_DIGITS', 6),

        /*
         * Accepted timesteps either side of the current one, for clock drift.
         * 1 means three candidate steps in total. Expressed in STEPS rather than
         * seconds because the replay guard records a step: a seconds-based
         * leeway cannot tell you which step was accepted, and a guard that
         * cannot name the step it consumed permits the replay it appears to
         * prevent (RFC 6238 §5.2).
         */
        'window' => (int) env('VOUCH_TOTP_WINDOW', 1),
    ],
```

- [ ] **Step 2: Write the failing test**

Create `tests/Factors/TotpFactorTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\AdvanceCredentialTimestep;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;
use OTPHP\TOTP;

uses(RefreshDatabase::class);

const TOTP_PERIOD = 30;

function totpFactor(): TotpFactor
{
    return app(TotpFactor::class);
}

function totpAttempt(?int $userId = 7): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => $userId,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ]);
}

/** Enrolls and returns the raw base32 seed, read out of the encrypted column. */
function enrollTotp(int $userId = 7): string
{
    totpFactor()->enroll($userId, ['label' => 'ada@acme.example']);

    return (string) AuthCredential::where('user_id', $userId)->where('type', 'totp')->firstOrFail()->secret;
}

function codeAt(string $secret, int $timestamp): string
{
    return TOTP::createFromSecret($secret, new \Fissible\Vouch\Support\SystemClock())->at($timestamp);
}

beforeEach(function (): void {
    // A fixed clock, so timestep arithmetic is deterministic rather than a
    // function of when the suite happened to run. SystemClock is Carbon-backed
    // precisely so travelTo() moves it.
    $this->travelTo('2026-08-13 12:00:00');
});

it('describes itself as a single possession factor', function (): void {
    expect(totpFactor()->id())->toBe('totp')
        ->and(totpFactor()->strength())->toBe(FactorStrength::Possession)
        ->and(totpFactor()->maxActiveCredentials())->toBe(1);
});

it('returns a provisioning uri as a one-time secret, not a plain string', function (): void {
    $result = totpFactor()->enroll(7, ['label' => 'ada@acme.example']);

    expect($result->credentials)->toHaveCount(1)
        ->and($result->secrets)->toHaveCount(1);

    $uri = $result->secrets[0]->reveal();

    expect($uri)->toStartWith('otpauth://totp/')
        ->and($uri)->toContain('issuer=');
});

it('encrypts the seed at rest', function (): void {
    totpFactor()->enroll(7, ['label' => 'ada@acme.example']);

    $raw = \Illuminate\Support\Facades\DB::table('auth_credentials')->where('user_id', 7)->value('secret');
    $model = AuthCredential::where('user_id', 7)->firstOrFail();

    expect($raw)->not->toBe($model->secret);
});

it('accepts the current code and advances the timestep', function (): void {
    $secret = enrollTotp();
    $now = now()->getTimestamp();

    $result = totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, $now)],
    ));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->mutations)->toHaveCount(1)
        ->and($result->mutations[0])->toBeInstanceOf(AdvanceCredentialTimestep::class)
        ->and($result->mutations[0]->timestep)->toBe(intdiv($now, TOTP_PERIOD));
});

it('accepts a code from the previous step within the drift window', function (): void {
    $secret = enrollTotp();
    $now = now()->getTimestamp();

    $result = totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, $now - TOTP_PERIOD)],
    ));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->mutations[0]->timestep)->toBe(intdiv($now, TOTP_PERIOD) - 1);
});

it('reports the timestep it actually matched, not the current one', function (): void {
    /*
     * The whole reason this driver does not use otphp's $leeway parameter.
     * verify() with a leeway returns bool and checks three timestamps
     * internally, so the matched step is unrecoverable — and a replay guard that
     * cannot name the step it consumed permits the replay it appears to prevent.
     */
    $secret = enrollTotp();
    $now = now()->getTimestamp();

    $previous = totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, $now - TOTP_PERIOD)],
    ));

    expect($previous->mutations[0]->timestep)->not->toBe(intdiv($now, TOTP_PERIOD));
});

it('rejects a code outside the drift window', function (): void {
    $secret = enrollTotp();
    $now = now()->getTimestamp();

    expect(totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, $now - (5 * TOTP_PERIOD))],
    ))->failure)->toBe(FactorFailure::Mismatch);
});

it('refuses a replay of the same code once the store has recorded it', function (): void {
    // RFC 6238 §5.2: an accepted OTP must not be accepted a second time.
    $secret = enrollTotp();
    $attempt = totpAttempt();
    $code = codeAt($secret, now()->getTimestamp());

    $first = totpFactor()->verify(new VerificationRequest($attempt, ['code' => $code]));
    expect(app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        ...$first->mutations,
    ))->toBe(TransitionOutcome::Succeeded);

    expect(totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => $code],
    ))->failure)->toBe(FactorFailure::Consumed);
});

it('refuses a replay across the leeway window, which a last_used_at guard would allow', function (): void {
    /*
     * The concrete case Amendment B exists for. A code from step T+1 is accepted
     * while the wall clock sits in period T. Deriving the timestep from a
     * last_used_at written at that moment yields T, so replaying the T+1 code
     * passes a `>` check again. Recording the matched STEP closes it.
     */
    $secret = enrollTotp();
    $now = now()->getTimestamp();
    $nextStepCode = codeAt($secret, $now + TOTP_PERIOD);
    $attempt = totpAttempt();

    $first = totpFactor()->verify(new VerificationRequest($attempt, ['code' => $nextStepCode]));
    expect($first->isSatisfied())->toBeTrue()
        ->and($first->mutations[0]->timestep)->toBe(intdiv($now, TOTP_PERIOD) + 1);

    app(AttemptStore::class)->transition($attempt, AttemptState::FactorSatisfied, ...$first->mutations);

    expect(totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => $nextStepCode],
    ))->failure)->toBe(FactorFailure::Consumed);
});

it('leaves the store as the authoritative replay guard', function (): void {
    /*
     * The driver's own last_used_timestep check is a fast path, not the
     * guarantee: two concurrent submissions can both read the old watermark
     * before either writes. This attacks the store's guarded predicate directly,
     * bypassing the driver, to prove the atomic guard is the real one.
     */
    $secret = enrollTotp();
    $credential = AuthCredential::where('user_id', 7)->firstOrFail();
    $step = intdiv(now()->getTimestamp(), TOTP_PERIOD);
    $attempt = totpAttempt();

    app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, $step),
    );

    expect(app(AttemptStore::class)->transition(
        totpAttempt(),
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, $step),
    ))->toBe(TransitionOutcome::TimestepReplay);
});

it('issues no challenge', function (): void {
    expect(totpFactor()->challenge(new \Fissible\Vouch\Factors\ChallengeRequest(totpAttempt())))->toBeNull();
});

it('reports malformed input rather than a mismatch', function (): void {
    enrollTotp();

    expect(totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => 12345],
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('never reports aal3-eligible attributes', function (): void {
    // NIST AAL3 requires a non-exportable private key in hardware. A TOTP seed
    // is neither, and defaulting these false is the fail-closed direction.
    $secret = enrollTotp();

    $result = totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, now()->getTimestamp())],
    ));

    expect($result->factor?->isMultiFactor)->toBeFalse()
        ->and($result->factor?->userVerified)->toBeFalse()
        ->and($result->factor?->phishingResistant)->toBeFalse();
});
```

- [ ] **Step 3: Run it and watch it fail**

Run: `vendor/bin/pest tests/Factors/TotpFactorTest.php`
Expected: FAIL — `TotpFactor` not found.

- [ ] **Step 4: Write `TotpFactor`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

use Fissible\Vouch\Attempts\Mutations\AdvanceCredentialTimestep;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Secrets\OneTimeSecret;
use InvalidArgumentException;
use OTPHP\TOTP;
use Psr\Clock\ClockInterface;

/**
 * RFC 6238 time-based one-time passwords, over spomky-labs/otphp.
 *
 * DELIBERATELY DOES NOT USE otphp's $leeway PARAMETER. TOTP::verify() returns
 * bool and, with a leeway, checks three timestamps internally — so the matched
 * timestep is unrecoverable. Amendment B needs that step to record it, and a
 * replay guard that cannot name the step it consumed permits exactly the replay
 * RFC 6238 §5.2 forbids. This driver iterates candidate steps and verifies each
 * exactly, at $step * $period with a null leeway.
 *
 * The driver's own watermark check is a fast path, not the guarantee. Two
 * concurrent submissions can both read the old watermark before either writes;
 * the store's guarded `last_used_timestep < :step` update is what makes the
 * guard atomic.
 */
final readonly class TotpFactor implements Factor
{
    public function __construct(
        private EnrollmentGuard $guard,
        private ClockInterface $clock,
        private string $issuer = 'Vouch',
        private int $period = 30,
        private int $digits = 6,
        private int $window = 1,
    ) {}

    public function id(): string
    {
        return 'totp';
    }

    public function kind(): FactorKind
    {
        return FactorKind::Possession;
    }

    public function strength(): FactorStrength
    {
        return FactorStrength::Possession;
    }

    public function maxActiveCredentials(): ?int
    {
        return 1;
    }

    /**
     * @param  array{label?: mixed, replace?: mixed}  $data
     */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        $label = $data['label'] ?? null;

        if (! is_string($label) || $label === '') {
            throw new InvalidArgumentException(
                'TotpFactor::enroll() requires a non-empty "label" string — it is what the '
                . 'authenticator app shows next to the code.',
            );
        }

        $replace = ($data['replace'] ?? false) === true;

        $totp = TOTP::generate($this->clock);
        $totp->setPeriod($this->period);
        $totp->setDigits($this->digits);
        $totp->setLabel($label);
        $totp->setIssuer($this->issuer);

        $secret = $totp->getSecret();

        $credential = $this->guard->serialize(
            $userId,
            $this->id(),
            $this->maxActiveCredentials(),
            function () use ($userId, $secret, $replace): AuthCredential {
                if ($replace) {
                    AuthCredential::query()
                        ->where('user_id', $userId)
                        ->where('type', $this->id())
                        ->whereNull('disabled_at')
                        ->update(['disabled_at' => $this->clock->now()]);
                }

                return AuthCredential::create([
                    'user_id' => $userId,
                    'type' => $this->id(),
                    // `encrypted` cast: the seed is a credential, not a label.
                    'secret' => $secret,
                    'strength' => $this->strength()->name,
                ]);
            },
        );

        return new EnrollmentResult(
            [$credential],
            [new OneTimeSecret($totp->getProvisioningUri())],
        );
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        return null;
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        $submitted = $request->string('code');

        if ($submitted === null) {
            return FactorResult::failed(FactorFailure::Malformed);
        }

        $userId = $request->attempt->user_id;

        if ($userId === null) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        $credential = AuthCredential::query()
            ->where('user_id', $userId)
            ->where('type', $this->id())
            ->whereNull('disabled_at')
            ->first();

        if (! $credential instanceof AuthCredential || ! is_string($credential->secret)) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        $matched = $this->matchTimestep($credential->secret, $submitted);

        if ($matched === null) {
            return FactorResult::failed(FactorFailure::Mismatch);
        }

        /*
         * Fast path only. The authoritative guard is the store's
         * `last_used_timestep IS NULL OR < :step` predicate, which is atomic;
         * this check exists so an obvious replay costs no transaction.
         */
        if ($credential->last_used_timestep !== null && $matched <= $credential->last_used_timestep) {
            return FactorResult::failed(FactorFailure::Consumed);
        }

        return FactorResult::satisfied(
            new SatisfiedFactor(
                factorId: $this->id(),
                credentialId: (string) $credential->id,
                kind: $this->kind(),
                strength: $this->strength(),
                // A TOTP seed is exportable software state: single-factor, no
                // user verification, and not phishing-resistant. AAL3 requires a
                // non-exportable hardware-held key, which this is not.
                isMultiFactor: false,
                userVerified: false,
                phishingResistant: false,
                authenticatorId: null,
                satisfiedAt: $this->clock->now(),
            ),
            new AdvanceCredentialTimestep($credential->id, $matched),
        );
    }

    public function revoke(AuthCredential $credential): void
    {
        $credential->update(['disabled_at' => $this->clock->now()]);
    }

    /**
     * Find which timestep the submitted code belongs to, or null.
     *
     * Candidates run newest-first so a code valid in more than one step — which
     * cannot happen with distinct secrets but is cheap to be deterministic
     * about — resolves to the highest step, advancing the watermark furthest.
     *
     * Every comparison goes through otphp's compareOTP(), which is hash_equals.
     */
    private function matchTimestep(string $secret, string $submitted): ?int
    {
        $totp = TOTP::createFromSecret($secret, $this->clock);
        $totp->setPeriod($this->period);
        $totp->setDigits($this->digits);

        $currentStep = intdiv($this->clock->now()->getTimestamp(), $this->period);

        for ($offset = $this->window; $offset >= -$this->window; $offset--) {
            $step = $currentStep + $offset;

            if ($step < 0) {
                continue;
            }

            // Null leeway: an EXACT comparison at this timestamp, so a match
            // identifies the step unambiguously.
            if ($totp->verify($submitted, $step * $this->period, null)) {
                return $step;
            }
        }

        return null;
    }
}
```

- [ ] **Step 5: Bind the driver**

In `src/VouchServiceProvider.php`'s `register()`:

```php
        $this->app->singleton(
            \Fissible\Vouch\Factors\Drivers\TotpFactor::class,
            fn ($app): \Fissible\Vouch\Factors\Drivers\TotpFactor => new \Fissible\Vouch\Factors\Drivers\TotpFactor(
                $app->make(\Fissible\Vouch\Enrollment\EnrollmentGuard::class),
                $app->make(\Psr\Clock\ClockInterface::class),
                (string) config('vouch.totp.issuer'),
                (int) config('vouch.totp.period'),
                (int) config('vouch.totp.digits'),
                (int) config('vouch.totp.window'),
            ),
        );
```

- [ ] **Step 6: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Factors/TotpFactorTest.php`
Expected: PASS, 13 tests.

If the drift-window tests fail at a period boundary, do **not** widen the window to make them green — `travelTo('2026-08-13 12:00:00')` puts the clock at a step boundary deliberately. A failure there is a real arithmetic bug in `matchTimestep()`.

- [ ] **Step 7: Prove the timestep guard is load-bearing, three ways**

```bash
cp src/Factors/Drivers/TotpFactor.php /tmp/tf.bak
```

1. Replace the candidate loop with otphp's leeway form — `$totp->verify($submitted, null, $this->period - 1)` — returning `$currentStep` on success. The "reports the timestep it actually matched" and "refuses a replay across the leeway window" tests must FAIL. **This is the finding that shaped the driver; if these stay green the tests are not pinning it.**
2. Change the driver's fast-path check to `$matched < $credential->last_used_timestep`. The straightforward replay test must FAIL.
3. Delete the driver's fast-path check entirely. The "leaves the store as the authoritative replay guard" test must still PASS — it attacks the store directly — while the replay tests that route through the driver now return `Consumed` from the store rather than the driver. If deleting the fast path breaks nothing at all, the store-level guard is not being exercised and needs a test that reaches it.

Restore after each:

```bash
cp /tmp/tf.bak src/Factors/Drivers/TotpFactor.php
vendor/bin/pest tests/Factors/TotpFactorTest.php   # green again
```

- [ ] **Step 8: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green. otphp's `TOTP` is `@readonly`-annotated but its setters mutate; if Larastan objects to `setPeriod()` on the generated instance, use the `withPeriod()`/`withDigits()` immutable variants and reassign, rather than suppressing the error.

- [ ] **Step 9: Commit**

```bash
git add src/Factors/Drivers/TotpFactor.php src/VouchServiceProvider.php config/vouch.php tests/Factors/TotpFactorTest.php
git commit -m "feat: add the TOTP driver with an explicit timestep replay guard

Does not use otphp's \$leeway parameter: verify() returns bool and checks
three timestamps internally, so the matched step is unrecoverable, and a
replay guard that cannot name the step it consumed permits the replay RFC
6238 §5.2 forbids. Iterates candidate steps and verifies each exactly."
```

---

## Task 10: The email and SMS OTP drivers

**Files:**
- Create: `src/Contracts/OtpDelivery.php`, `src/Notifications/UnconfiguredOtpDelivery.php`, `src/Factors/Drivers/OtpFactor.php`, `src/Factors/Drivers/EmailOtpFactor.php`, `src/Factors/Drivers/SmsOtpFactor.php`, `tests/Support/ArrayOtpDelivery.php`
- Modify: `config/vouch.php`, `src/VouchServiceProvider.php`
- Test: `tests/Factors/OtpFactorTest.php`

**Interfaces:**
- Consumes: `ConsumeChallenge` from Task 5; `EnrollmentGuard` from Task 6; the Task 7 value objects; `auth_credentials.identifier_id` and `auth_challenges.credential_id` from Task 2; `GuardsChallengeTarget` from Task 4
- Produces:
  - `Fissible\Vouch\Contracts\OtpDelivery::deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void`
  - `OtpFactor` abstract — `__construct(EnrollmentGuard $guard, ClockInterface $clock, OtpDelivery $delivery, int $length, int $ttlSeconds)`
  - `EmailOtpFactor` (`id()` = `'email_otp'`, identifier type `'email'`), `SmsOtpFactor` (`id()` = `'sms_otp'`, identifier type `'phone'`)
  - config keys `vouch.otp.length`, `vouch.otp.ttl_seconds`

The two concrete drivers differ only in their type key and the identifier type they accept, so they share an abstract base. This is the only task that exercises `ChallengeRequest`, `bound_ip`/`bound_user_agent`, and Amendment A's re-enrollment rule.

- [ ] **Step 1: Add the config section**

In `config/vouch.php`, add before the closing `];`:

```php
    'otp' => [
        /*
         * Digits per code. Generated with random_int(), a CSPRNG — rand() and
         * mt_rand() are predictable from observed output and must never appear
         * on this path.
         */
        'length' => (int) env('VOUCH_OTP_LENGTH', 6),

        // Short by design: a six-digit code is only 20 bits.
        'ttl_seconds' => (int) env('VOUCH_OTP_TTL', 120),
    ],
```

- [ ] **Step 2: Write the delivery contract and the unconfigured default**

`src/Contracts/OtpDelivery.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use DateTimeImmutable;
use Fissible\Vouch\Models\AuthIdentifier;

/**
 * Delivers a one-time code to a verified identifier.
 *
 * A seam rather than an implementation: vouch depends on neither a mail
 * transport nor an SMS gateway, and the host decides both. The plaintext code
 * exists only in this call — it is never stored, never logged, and never
 * returned to the caller.
 */
interface OtpDelivery
{
    public function deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void;
}
```

`src/Notifications/UnconfiguredOtpDelivery.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

use DateTimeImmutable;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use RuntimeException;

/**
 * The default binding: fails loudly rather than dropping codes.
 *
 * Deliberately not a no-op and deliberately not a log writer. A no-op turns
 * "OTP is not wired up" into "OTP silently never arrives", and a log writer
 * would put a live authentication code into a log file, which is a credential
 * disclosure in the one place everybody greps.
 */
final class UnconfiguredOtpDelivery implements OtpDelivery
{
    public function deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void
    {
        throw new RuntimeException(
            'No OTP delivery is configured. Bind Fissible\Vouch\Contracts\OtpDelivery to an '
            . 'implementation that sends mail or SMS. Vouch refuses to guess: a no-op would '
            . 'make codes silently never arrive, and logging the code would disclose a live '
            . 'credential.',
        );
    }
}
```

- [ ] **Step 3: Write the test double**

`tests/Support/ArrayOtpDelivery.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use DateTimeImmutable;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;

/**
 * Captures delivered codes so tests can assert on what was actually sent.
 *
 * A real double rather than a mock: the assertions that matter here are about
 * WHICH identifier received WHICH code, and a mock verifying "deliver was
 * called once" would pass while sending to the wrong address.
 */
final class ArrayOtpDelivery implements OtpDelivery
{
    /** @var list<array{identifier: AuthIdentifier, code: string, expiresAt: DateTimeImmutable}> */
    public array $sent = [];

    public function deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void
    {
        $this->sent[] = ['identifier' => $identifier, 'code' => $code, 'expiresAt' => $expiresAt];
    }

    public function lastCode(): string
    {
        return $this->sent[count($this->sent) - 1]['code'];
    }

    public function lastIdentifier(): AuthIdentifier
    {
        return $this->sent[count($this->sent) - 1]['identifier'];
    }
}
```

- [ ] **Step 4: Write the failing test**

Create `tests/Factors/OtpFactorTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\SmsOtpFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $this->delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $this->delivery);
});

function emailOtp(): EmailOtpFactor
{
    return app(EmailOtpFactor::class);
}

function otpAttempt(?int $userId = 7): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => $userId,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ]);
}

function verifiedEmail(int $userId = 7, string $value = 'ada@acme.example'): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);
}

it('describes itself as a weak possession factor with no cardinality limit', function (): void {
    expect(emailOtp()->id())->toBe('email_otp')
        ->and(emailOtp()->strength())->toBe(FactorStrength::PossessionWeak)
        ->and(emailOtp()->maxActiveCredentials())->toBeNull();
});

it('enrolls a secretless credential bound to a verified identifier', function (): void {
    $identifier = verifiedEmail();

    $result = emailOtp()->enroll(7, ['identifier_id' => $identifier->id]);

    expect($result->credentials)->toHaveCount(1)
        ->and($result->secrets)->toBe([])
        ->and($result->credentials[0]->identifier_id)->toBe($identifier->id)
        ->and($result->credentials[0]->secret)->toBeNull();
});

it('re-enables rather than duplicating on re-enrollment, preserving the credential id', function (): void {
    /*
     * The unique (user_id, type, identifier_id) index counts disabled rows, and
     * a partial index is not portable across the three engines. Preserving the
     * ID keeps auth_token_assurances.credential_ids references and kernel
     * distinctness coherent — a new row would silently orphan both.
     *
     * Honest only because OTP credentials are secretless: the code lives in
     * auth_challenges, so re-enrollment genuinely IS re-enabling. Password and
     * TOTP must still create a fresh row with a new secret.
     */
    $identifier = verifiedEmail();
    $first = emailOtp()->enroll(7, ['identifier_id' => $identifier->id])->credentials[0];
    emailOtp()->revoke($first);

    $second = emailOtp()->enroll(7, ['identifier_id' => $identifier->id])->credentials[0];

    expect($second->id)->toBe($first->id)
        ->and($second->disabled_at)->toBeNull()
        ->and(AuthCredential::where('user_id', 7)->count())->toBe(1);
});

it('refuses to enroll against an unverified identifier', function (): void {
    $identifier = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'unproven@acme.example', 'verified_at' => null,
    ]);

    emailOtp()->enroll(7, ['identifier_id' => $identifier->id]);
})->throws(\Fissible\Vouch\Persistence\IdentifierLinkageViolation::class);

it('refuses to enroll against an identifier of the wrong type', function (): void {
    // A phone number is not an email address. Without this the SMS and email
    // drivers would each happily deliver to the other's identifiers.
    $phone = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'phone', 'value' => '+15550100', 'verified_at' => now(),
    ]);

    emailOtp()->enroll(7, ['identifier_id' => $phone->id]);
})->throws(InvalidArgumentException::class);

it('delivers a code and records the challenge against the credential', function (): void {
    $identifier = verifiedEmail();
    $credential = emailOtp()->enroll(7, ['identifier_id' => $identifier->id])->credentials[0];
    $attempt = otpAttempt();

    $challenge = emailOtp()->challenge(new ChallengeRequest(
        attempt: $attempt,
        credential: $credential,
        clientIp: '198.51.100.7',
        clientUserAgent: 'Mozilla/5.0',
    ));

    expect($challenge)->toBeInstanceOf(AuthChallenge::class)
        ->and($challenge->credential_id)->toBe($credential->id)
        ->and($challenge->bound_ip)->toBe('198.51.100.7')
        ->and($challenge->bound_user_agent)->toBe('Mozilla/5.0')
        ->and($this->delivery->lastIdentifier()->id)->toBe($identifier->id);
});

it('never stores the delivered code in plaintext', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];

    $challenge = emailOtp()->challenge(new ChallengeRequest(otpAttempt(), $credential));

    expect($challenge->code_hash)->not->toBe($this->delivery->lastCode())
        ->and($challenge->getAttributes())->not->toHaveKey('code');
});

it('generates a code of the configured length, all digits', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    emailOtp()->challenge(new ChallengeRequest(otpAttempt(), $credential));

    expect($this->delivery->lastCode())->toHaveLength(6)
        ->and($this->delivery->lastCode())->toMatch('/^\d{6}$/');
});

it('satisfies with the delivered code and returns a consume mutation', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential, '198.51.100.7', 'UA'));

    $result = emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $this->delivery->lastCode()],
        challenge: $challenge,
        clientIp: '198.51.100.7',
        clientUserAgent: 'UA',
    ));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->mutations)->toHaveCount(1)
        ->and($result->mutations[0])->toBeInstanceOf(ConsumeChallenge::class);
});

it('reports the credential the code was actually delivered against', function (): void {
    /*
     * The reason Amendment D exists. With OTP on two verified addresses, a code
     * delivered to one must not be attributed to the other — require_distinct_
     * credentials keys on this value, and would otherwise pass while describing
     * a delivery that never happened.
     */
    $first = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail(7, 'ada@acme.example')->id])->credentials[0];
    $second = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail(7, 'ada+alt@acme.example')->id])->credentials[0];

    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $second));

    $result = emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $this->delivery->lastCode()],
        challenge: $challenge,
    ));

    expect($result->factor?->credentialId)->toBe((string) $second->id)
        ->and($result->factor?->credentialId)->not->toBe((string) $first->id);
});

it('refuses a code submitted from a different ip', function (): void {
    // bound_ip written and never read would be the vacuous-control shape this
    // project keeps finding. This is the test that makes it load-bearing.
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential, '198.51.100.7', 'UA'));

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $this->delivery->lastCode()],
        challenge: $challenge,
        clientIp: '203.0.113.9',
        clientUserAgent: 'UA',
    ))->failure)->toBe(FactorFailure::BindingMismatch);
});

it('refuses a code submitted from a different user agent', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential, '198.51.100.7', 'UA'));

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $this->delivery->lastCode()],
        challenge: $challenge,
        clientIp: '198.51.100.7',
        clientUserAgent: 'SomethingElse',
    ))->failure)->toBe(FactorFailure::BindingMismatch);
});

it('refuses a wrong code without consuming the challenge', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential));

    $result = emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => '000000'],
        challenge: $challenge,
    ));

    expect($result->failure)->toBe(FactorFailure::Mismatch)
        ->and($result->mutations)->toBe([])
        ->and(AuthChallenge::findOrFail($challenge->id)->consumed_at)->toBeNull();
});

it('refuses an expired challenge', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential));
    $code = $this->delivery->lastCode();

    $this->travel(5)->minutes();

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: $challenge,
    ))->failure)->toBe(FactorFailure::Expired);
});

it('refuses a challenge already consumed by the store', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential));
    $code = $this->delivery->lastCode();

    $first = emailOtp()->verify(new VerificationRequest($attempt, ['code' => $code], challenge: $challenge));
    expect(app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        ...$first->mutations,
    ))->toBe(TransitionOutcome::Succeeded);

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: AuthChallenge::findOrFail($challenge->id),
    ))->failure)->toBe(FactorFailure::Consumed);
});

it('refuses a challenge belonging to a different attempt', function (): void {
    // Otherwise a challenge id observed elsewhere could be redeemed here.
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $challenge = emailOtp()->challenge(new ChallengeRequest(otpAttempt(), $credential));

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: otpAttempt(),
        input: ['code' => $this->delivery->lastCode()],
        challenge: $challenge,
    ))->failure)->toBe(FactorFailure::BindingMismatch);
});

it('refuses to challenge when the user has several otp credentials and none was named', function (): void {
    // Choosing one silently would deliver to an address the user did not pick.
    emailOtp()->enroll(7, ['identifier_id' => verifiedEmail(7, 'ada@acme.example')->id]);
    emailOtp()->enroll(7, ['identifier_id' => verifiedEmail(7, 'ada+alt@acme.example')->id]);

    emailOtp()->challenge(new ChallengeRequest(otpAttempt()));
})->throws(InvalidArgumentException::class);

it('resolves the only otp credential when none was named', function (): void {
    emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id]);

    expect(emailOtp()->challenge(new ChallengeRequest(otpAttempt())))->toBeInstanceOf(AuthChallenge::class);
});

it('keeps the sms driver on its own type key and identifier type', function (): void {
    $sms = app(SmsOtpFactor::class);
    $phone = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'phone', 'value' => '+15550100', 'verified_at' => now(),
    ]);

    $credential = $sms->enroll(7, ['identifier_id' => $phone->id])->credentials[0];

    expect($sms->id())->toBe('sms_otp')
        ->and($credential->type)->toBe('sms_otp');
});
```

- [ ] **Step 5: Run it and watch it fail**

Run: `vendor/bin/pest tests/Factors/OtpFactorTest.php`
Expected: FAIL — `EmailOtpFactor` not found.

- [ ] **Step 6: Write the abstract `OtpFactor`**

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Illuminate\Support\Facades\Hash;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;

/**
 * Shared behaviour for the email and SMS one-time-password drivers.
 *
 * No library sits underneath these. `spatie/laravel-one-time-passwords` was
 * evaluated and rejected: it ships its own table and requires a trait on the
 * host's authenticatable model, which breaks both vouch's rule against touching
 * the host user class and the rule that the STORE owns every single-use
 * mutation — it cannot, for a table it does not control.
 *
 * So: random_int() for generation, the host-configured Hash driver for storage
 * and constant-time comparison, vouch's own auth_challenges for state, and an
 * OtpDelivery seam for transport.
 */
abstract readonly class OtpFactor implements Factor
{
    public function __construct(
        protected EnrollmentGuard $guard,
        protected ClockInterface $clock,
        protected OtpDelivery $delivery,
        protected int $length = 6,
        protected int $ttlSeconds = 120,
    ) {}

    /** The auth_identifiers.type this driver delivers to. */
    abstract protected function identifierType(): string;

    public function kind(): FactorKind
    {
        return FactorKind::Possession;
    }

    public function strength(): FactorStrength
    {
        return FactorStrength::PossessionWeak;
    }

    /**
     * Unbounded: naturally limited by how many identifiers the user has verified,
     * and the unique (user_id, type, identifier_id) index stops duplicates per
     * address.
     */
    public function maxActiveCredentials(): ?int
    {
        return null;
    }

    /**
     * Enroll — or RE-ENABLE — this user's credential for one verified identifier.
     *
     * Re-enabling rather than inserting is required because the unique index
     * counts disabled rows and a partial index is not portable across the three
     * engines. It preserves the credential ID, so auth_token_assurances
     * references and kernel distinctness stay coherent.
     *
     * This asymmetry is honest ONLY because OTP credentials are secretless: the
     * code lives in auth_challenges, so re-enrollment genuinely is re-enabling.
     * Password and TOTP re-enrollment must still create a fresh row.
     *
     * @param  array{identifier_id?: mixed}  $data
     */
    public function enroll(int $userId, array $data): EnrollmentResult
    {
        $identifierId = $data['identifier_id'] ?? null;

        if (! is_int($identifierId)) {
            throw new InvalidArgumentException(sprintf(
                '%s::enroll() requires an integer "identifier_id".',
                static::class,
            ));
        }

        $identifier = AuthIdentifier::query()->find($identifierId);

        if (! $identifier instanceof AuthIdentifier) {
            throw new InvalidArgumentException(sprintf('Identifier %d does not exist.', $identifierId));
        }

        if ($identifier->type !== $this->identifierType()) {
            throw new InvalidArgumentException(sprintf(
                '%s delivers to "%s" identifiers, but identifier %d is a "%s". Delivering an '
                . 'SMS code to an email address, or the reverse, would send it nowhere useful.',
                static::class,
                $this->identifierType(),
                $identifierId,
                $identifier->type,
            ));
        }

        /*
         * Same-user and verified are NOT re-checked here. GuardsIdentifierLinkage
         * enforces both on the model write path, so they hold however the row is
         * created — including by code that never read this method.
         */
        $credential = $this->guard->serialize(
            $userId,
            $this->id(),
            $this->maxActiveCredentials(),
            function () use ($userId, $identifierId): AuthCredential {
                $existing = AuthCredential::query()
                    ->where('user_id', $userId)
                    ->where('type', $this->id())
                    ->where('identifier_id', $identifierId)
                    ->first();

                if ($existing instanceof AuthCredential) {
                    // Preserve the ID. A new row would orphan every existing
                    // token-assurance reference to this credential.
                    $existing->update(['disabled_at' => null]);

                    return $existing->refresh();
                }

                return AuthCredential::create([
                    'user_id' => $userId,
                    'type' => $this->id(),
                    'identifier_id' => $identifierId,
                    'secret' => null,
                    'strength' => $this->strength()->name,
                ]);
            },
        );

        // No one-time secrets: an OTP credential holds nothing to show.
        return new EnrollmentResult([$credential]);
    }

    public function challenge(ChallengeRequest $request): ?AuthChallenge
    {
        $credential = $request->credential ?? $this->resolveSoleCredential($request);
        $identifier = AuthIdentifier::query()->findOrFail($credential->identifier_id);

        $code = $this->generateCode();
        $expiresAt = $this->clock->now()->modify(sprintf('+%d seconds', $this->ttlSeconds));

        /*
         * The challenge row is written BEFORE delivery. If delivery throws, the
         * user gets a code that was never sent and the challenge expires
         * harmlessly; the reverse order risks a delivered code with no row to
         * verify it against, which locks the user out of a factor they hold.
         *
         * GuardsChallengeTarget validates credential_id here — active, same
         * user, identifier-linked — so an unusable target cannot be persisted.
         */
        $challenge = AuthChallenge::create([
            'attempt_id' => $request->attempt->id,
            'credential_id' => $credential->id,
            'factor_type' => $this->id(),
            'code_hash' => Hash::make($code),
            'bound_ip' => $request->clientIp,
            'bound_user_agent' => $request->clientUserAgent,
            'expires_at' => $expiresAt,
        ]);

        $this->delivery->deliver($identifier, $code, $expiresAt);

        return $challenge;
    }

    public function verify(VerificationRequest $request): FactorResult
    {
        $submitted = $request->string('code');

        if ($submitted === null) {
            return FactorResult::failed(FactorFailure::Malformed);
        }

        $challenge = $request->challenge ?? $this->resolveLatestChallenge($request);

        if (! $challenge instanceof AuthChallenge) {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        if ($challenge->attempt_id !== $request->attempt->id || $challenge->factor_type !== $this->id()) {
            return FactorResult::failed(FactorFailure::BindingMismatch);
        }

        if ($challenge->consumed_at !== null) {
            return FactorResult::failed(FactorFailure::Consumed);
        }

        if ($challenge->expires_at->getTimestamp() <= $this->clock->now()->getTimestamp()) {
            return FactorResult::failed(FactorFailure::Expired);
        }

        /*
         * Binding is checked BEFORE the code comparison, and this is the whole
         * reason VerificationRequest carries client context: bound_ip and
         * bound_user_agent are written at delivery, and a driver that could not
         * read them would leave them stored and never evaluated.
         */
        if (! $this->bindingMatches($challenge, $request)) {
            return FactorResult::failed(FactorFailure::BindingMismatch);
        }

        if (! Hash::check($submitted, $challenge->code_hash)) {
            return FactorResult::failed(FactorFailure::Mismatch);
        }

        $credentialId = $challenge->credential_id;

        if ($credentialId === null) {
            // GuardsChallengeTarget makes this unreachable for OTP; failing
            // closed rather than inventing a credential id keeps it that way.
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        return FactorResult::satisfied(
            new SatisfiedFactor(
                factorId: $this->id(),
                // Read from the challenge, never inferred: this is the record of
                // what was actually delivered.
                credentialId: (string) $credentialId,
                kind: $this->kind(),
                strength: $this->strength(),
                isMultiFactor: false,
                userVerified: false,
                phishingResistant: false,
                authenticatorId: null,
                satisfiedAt: $this->clock->now(),
            ),
            new ConsumeChallenge($challenge->id, $request->attempt->id),
        );
    }

    public function revoke(AuthCredential $credential): void
    {
        $credential->update(['disabled_at' => $this->clock->now()]);
    }

    /**
     * A null bound value means the challenge was issued without that context and
     * cannot constrain anything. A non-null one must match exactly.
     */
    private function bindingMatches(AuthChallenge $challenge, VerificationRequest $request): bool
    {
        if ($challenge->bound_ip !== null && $challenge->bound_ip !== $request->clientIp) {
            return false;
        }

        return ! ($challenge->bound_user_agent !== null
            && $challenge->bound_user_agent !== $request->clientUserAgent);
    }

    private function resolveSoleCredential(ChallengeRequest $request): AuthCredential
    {
        $userId = $request->attempt->user_id;

        if ($userId === null) {
            throw new InvalidArgumentException(
                'Cannot issue an OTP challenge for an attempt with no identified user.',
            );
        }

        $candidates = AuthCredential::query()
            ->where('user_id', $userId)
            ->where('type', $this->id())
            ->whereNull('disabled_at')
            ->get();

        if ($candidates->count() !== 1) {
            throw new InvalidArgumentException(sprintf(
                'ChallengeRequest named no credential and user %d has %d active %s credentials. '
                . 'Choosing one silently would deliver a code to an address the user did not pick.',
                $userId,
                $candidates->count(),
                $this->id(),
            ));
        }

        return $candidates->first();
    }

    private function resolveLatestChallenge(VerificationRequest $request): ?AuthChallenge
    {
        return AuthChallenge::query()
            ->where('attempt_id', $request->attempt->id)
            ->where('factor_type', $this->id())
            ->whereNull('consumed_at')
            ->latest('id')
            ->first();
    }

    /**
     * random_int() is a CSPRNG. A six-digit code is only about 20 bits, so a
     * predictable generator would make it trivially guessable rather than merely
     * weak — which is why the TTL is short and rate limiting arrives in 2.3.
     */
    private function generateCode(): string
    {
        $code = '';

        for ($i = 0; $i < $this->length; $i++) {
            $code .= (string) random_int(0, 9);
        }

        return $code;
    }
}
```

- [ ] **Step 7: Write the two concrete drivers**

`src/Factors/Drivers/EmailOtpFactor.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

final readonly class EmailOtpFactor extends OtpFactor
{
    public function id(): string
    {
        return 'email_otp';
    }

    protected function identifierType(): string
    {
        return 'email';
    }
}
```

`src/Factors/Drivers/SmsOtpFactor.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

final readonly class SmsOtpFactor extends OtpFactor
{
    public function id(): string
    {
        return 'sms_otp';
    }

    protected function identifierType(): string
    {
        return 'phone';
    }
}
```

- [ ] **Step 8: Bind the drivers and the delivery default**

In `src/VouchServiceProvider.php`'s `register()`:

```php
        $this->app->bind(
            \Fissible\Vouch\Contracts\OtpDelivery::class,
            \Fissible\Vouch\Notifications\UnconfiguredOtpDelivery::class,
        );

        foreach ([
            \Fissible\Vouch\Factors\Drivers\EmailOtpFactor::class,
            \Fissible\Vouch\Factors\Drivers\SmsOtpFactor::class,
        ] as $driver) {
            $this->app->singleton($driver, fn ($app) => new $driver(
                $app->make(\Fissible\Vouch\Enrollment\EnrollmentGuard::class),
                $app->make(\Psr\Clock\ClockInterface::class),
                $app->make(\Fissible\Vouch\Contracts\OtpDelivery::class),
                (int) config('vouch.otp.length'),
                (int) config('vouch.otp.ttl_seconds'),
            ));
        }
```

Note: the drivers are singletons but `OtpDelivery` is resolved at construction, so a test rebinding `OtpDelivery` must do so **before** first resolving a driver. The test's `beforeEach` does exactly that. If a test rebinds afterwards and sees stale delivery, that is the cause — do not switch the drivers to resolving the container at call time to paper over it.

- [ ] **Step 9: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Factors/OtpFactorTest.php`
Expected: PASS, 19 tests.

- [ ] **Step 10: Prove the binding check and the challenge target are load-bearing**

```bash
cp src/Factors/Drivers/OtpFactor.php /tmp/of.bak
```

1. Make `bindingMatches()` `return true;`. The two binding tests must FAIL. **This is the check that turns `bound_ip` from a stored value into a guard**; if they stay green, the columns are decoration.
2. Change `credentialId:` in the satisfied result to resolve the user's first active OTP credential instead of reading `$challenge->credential_id`. The "reports the credential the code was actually delivered against" test must FAIL. If it passes, the test is not distinguishing the two addresses and needs a stronger fixture.
3. Move `$this->delivery->deliver(...)` to before `AuthChallenge::create(...)`. Every test still passes — ordering is not observable from outside — so add nothing here; the comment in the code is the record. Note this in the task report rather than inventing a test that asserts on statement order.

Restore:

```bash
cp /tmp/of.bak src/Factors/Drivers/OtpFactor.php
vendor/bin/pest tests/Factors/OtpFactorTest.php   # green again
```

- [ ] **Step 11: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green. `abstract readonly class` with `final readonly` subclasses is valid in PHP 8.4; if Larastan objects to the promoted `protected` properties in a readonly abstract, keep them promoted and report the error rather than dropping `readonly`.

- [ ] **Step 12: Commit**

```bash
git add src/Contracts/OtpDelivery.php src/Notifications src/Factors/Drivers/OtpFactor.php src/Factors/Drivers/EmailOtpFactor.php src/Factors/Drivers/SmsOtpFactor.php src/VouchServiceProvider.php config/vouch.php tests/Support/ArrayOtpDelivery.php tests/Factors/OtpFactorTest.php
git commit -m "feat: add the email and SMS OTP drivers

No OTP library: vouch's own auth_challenges with random_int and Hash. The
satisfied credential is read from the challenge row rather than inferred, and
bound_ip/bound_user_agent are compared before the code, which is what makes
them guards rather than stored decoration. Unconfigured delivery throws
rather than no-opping or logging a live code."
```

---

## Task 11: Service-provider wiring and the factor registry

**Files:**
- Modify: `src/VouchServiceProvider.php`
- Test: `tests/Database/ServiceProviderTest.php`, `tests/Factors/RegistryWiringTest.php`

**Interfaces:**
- Consumes: all five drivers, `FactorRegistry`, `EnrollmentGuard`, `SystemClock`, `OtpDelivery`
- Produces: `app(FactorRegistry::class)` resolving with all five drivers registered

By this point the provider has accumulated bindings task by task. This task consolidates them into one readable `register()`, adds the registry, and pins the wiring with tests — so a missing driver is a test failure rather than a runtime surprise in 2.3.

- [ ] **Step 1: Write the failing wiring test**

Create `tests/Factors/RegistryWiringTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\Drivers\SmsOtpFactor;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Support\SystemClock;
use Psr\Clock\ClockInterface;

it('registers all five drivers under their credential type keys', function (): void {
    // The keys must match auth_credentials.type exactly. A mismatch would mean a
    // stored credential no driver can verify -- a lockout, discovered in 2.3.
    $registry = app(FactorRegistry::class);

    expect(array_map(fn ($f): string => $f->id(), $registry->all()))
        ->toEqualCanonicalizing(['password', 'totp', 'email_otp', 'sms_otp', 'recovery_code']);
});

it('resolves each driver to its expected class', function (): void {
    $registry = app(FactorRegistry::class);

    expect($registry->get('password'))->toBeInstanceOf(PasswordFactor::class)
        ->and($registry->get('totp'))->toBeInstanceOf(TotpFactor::class)
        ->and($registry->get('email_otp'))->toBeInstanceOf(EmailOtpFactor::class)
        ->and($registry->get('sms_otp'))->toBeInstanceOf(SmsOtpFactor::class)
        ->and($registry->get('recovery_code'))->toBeInstanceOf(RecoveryCodeFactor::class);
});

it('does not register passkey, which is 2.2b', function (): void {
    expect(app(FactorRegistry::class)->has('passkey'))->toBeFalse();
});

it('returns one shared registry rather than rebuilding it', function (): void {
    expect(app(FactorRegistry::class))->toBe(app(FactorRegistry::class));
});

it('binds a psr clock', function (): void {
    expect(app(ClockInterface::class))->toBeInstanceOf(SystemClock::class);
});

it('binds an enrollment guard', function (): void {
    expect(app(EnrollmentGuard::class))->toBeInstanceOf(EnrollmentGuard::class);
});

it('defaults otp delivery to something that throws rather than something silent', function (): void {
    // A no-op default would make "OTP is not configured" indistinguishable from
    // "the code never arrived", and only in production.
    expect(app(OtpDelivery::class))->toBeInstanceOf(UnconfiguredOtpDelivery::class);
});

it('carries the cardinality rule each driver declares in the spec', function (): void {
    $registry = app(FactorRegistry::class);

    expect($registry->get('password')->maxActiveCredentials())->toBe(1)
        ->and($registry->get('totp')->maxActiveCredentials())->toBe(1)
        ->and($registry->get('recovery_code')->maxActiveCredentials())->toBe(10)
        ->and($registry->get('email_otp')->maxActiveCredentials())->toBeNull()
        ->and($registry->get('sms_otp')->maxActiveCredentials())->toBeNull();
});

it('reports every driver as single-factor and not phishing-resistant', function (): void {
    /*
     * All five are genuinely both, so this pins a fact rather than a limitation.
     * It exists because those three SatisfiedFactor attributes get no `true`
     * until passkeys land in 2.2b, and a driver that started claiming
     * phishing_resistant would otherwise satisfy a high-assurance policy
     * silently.
     */
    foreach (app(FactorRegistry::class)->all() as $factor) {
        expect($factor->strength()->name)->not->toBe('PossessionStrong');
    }
});
```

- [ ] **Step 2: Run it and watch it fail**

Run: `vendor/bin/pest tests/Factors/RegistryWiringTest.php`
Expected: FAIL — `FactorRegistry` is not bound.

- [ ] **Step 3: Consolidate `register()`**

Replace the body of `register()` in `src/VouchServiceProvider.php` with this, keeping the existing `TenantResolver` and `AttemptStore` bindings and the `AuditSink` comment exactly as they are:

```php
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/vouch.php', 'vouch');

        $this->app->bind(TenantResolver::class, NullTenantResolver::class);

        $this->app->singleton(ClockInterface::class, SystemClock::class);

        /*
         * Unconfigured by default, and it THROWS. A no-op would turn "OTP is not
         * wired up" into "codes silently never arrive", and a log-writing default
         * would put a live authentication code into the one file everybody greps.
         */
        $this->app->bind(OtpDelivery::class, UnconfiguredOtpDelivery::class);

        $this->app->singleton(
            AttemptStore::class,
            fn ($app): DatabaseAttemptStore => new DatabaseAttemptStore(
                $app['db']->connection(),
                new TransitionRules(),
            ),
        );

        $this->app->singleton(
            EnrollmentGuard::class,
            fn ($app): EnrollmentGuard => new EnrollmentGuard(
                $app['db']->connection(),
                (int) config('vouch.enrollment.lock_wait_seconds'),
            ),
        );

        $this->registerFactorDrivers();

        /*
         * AuditSink is deliberately left unbound. Its drivers ship in Phase 2.4;
         * a host resolving it before then should get a clear container error
         * rather than a silent no-op that discards audit events.
         */
    }

    /**
     * The five drivers of Phase 2.2, plus the registry that resolves them.
     *
     * Passkey is absent on purpose — sub-project 2.2b, gated on evaluating
     * laravel/passkeys, which is pre-1.0.
     */
    private function registerFactorDrivers(): void
    {
        $this->app->singleton(
            PasswordFactor::class,
            fn ($app): PasswordFactor => new PasswordFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
            ),
        );

        $this->app->singleton(
            TotpFactor::class,
            fn ($app): TotpFactor => new TotpFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                (string) config('vouch.totp.issuer'),
                (int) config('vouch.totp.period'),
                (int) config('vouch.totp.digits'),
                (int) config('vouch.totp.window'),
            ),
        );

        $this->app->singleton(
            RecoveryCodeFactor::class,
            fn ($app): RecoveryCodeFactor => new RecoveryCodeFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                (int) config('vouch.recovery.count'),
                (int) config('vouch.recovery.length'),
            ),
        );

        $this->app->singleton(
            EmailOtpFactor::class,
            fn ($app): EmailOtpFactor => new EmailOtpFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                $app->make(OtpDelivery::class),
                (int) config('vouch.otp.length'),
                (int) config('vouch.otp.ttl_seconds'),
            ),
        );

        $this->app->singleton(
            SmsOtpFactor::class,
            fn ($app): SmsOtpFactor => new SmsOtpFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                $app->make(OtpDelivery::class),
                (int) config('vouch.otp.length'),
                (int) config('vouch.otp.ttl_seconds'),
            ),
        );

        $this->app->singleton(FactorRegistry::class, function ($app): FactorRegistry {
            $registry = new FactorRegistry();

            foreach ([
                PasswordFactor::class,
                TotpFactor::class,
                EmailOtpFactor::class,
                SmsOtpFactor::class,
                RecoveryCodeFactor::class,
            ] as $driver) {
                $registry->register($app->make($driver));
            }

            return $registry;
        });
    }
```

Add the imports this needs at the top of the file:

```php
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\Drivers\SmsOtpFactor;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Support\SystemClock;
use Psr\Clock\ClockInterface;
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `vendor/bin/pest tests/Factors/RegistryWiringTest.php`
Expected: PASS, 9 tests.

- [ ] **Step 5: Extend the existing provider test**

Append to `tests/Database/ServiceProviderTest.php`:

```php
it('publishes the new config sections', function (): void {
    // A key added to config/vouch.php but never merged reads as configurable
    // while silently using a hardcoded default.
    expect(config('vouch.totp.issuer'))->not->toBeNull()
        ->and(config('vouch.otp.ttl_seconds'))->toBeInt()
        ->and(config('vouch.recovery.count'))->toBe(10)
        ->and(config('vouch.enrollment.lock_wait_seconds'))->toBeInt()
        ->and(config('vouch.challenges.require_credential'))->toBe(['email_otp', 'sms_otp']);
});
```

- [ ] **Step 6: Run the full suite and the analyser**

Run: `composer test && composer stan`
Expected: both green.

- [ ] **Step 7: Confirm the kernel boundary still holds**

The whole phase added Laravel-facing code beside the kernel. Verify nothing leaked in:

```bash
vendor/bin/pest tests/Arch
git diff --stat main -- src/Kernel
```

Expected: the arch suite passes and `git diff` reports **no changes under `src/Kernel/`**. If a kernel file changed, that is a boundary violation regardless of what the arch scan says — the scans are a denylist, not a proof.

- [ ] **Step 8: Commit**

```bash
git add src/VouchServiceProvider.php tests/Factors/RegistryWiringTest.php tests/Database/ServiceProviderTest.php
git commit -m "feat: wire the five drivers into a shared FactorRegistry

Registry keys are asserted against auth_credentials.type values, so a
mismatch is a test failure here rather than an unverifiable stored credential
discovered in 2.3. Passkey is deliberately absent."
```

---

## Task 12: The cross-engine contention proof — completion gate

**Files:**
- Create: `tests/Concurrency/EnrollmentContentionTest.php`
- Modify: `.github/workflows/ci.yml`, `PROJECT.md`
- Test: the whole suite, on SQLite, MySQL 8 and Postgres 16

**Interfaces:**
- Consumes: `EnrollmentGuard` from Task 6; all five drivers
- Produces: a recorded, reproducible three-engine run

**This is a hard completion gate, not a follow-up.** Phase 2.2 is not complete until every leg passes. `maxActiveCredentials()` is a comment until serialization is demonstrated, and a single-connection test cannot demonstrate it — SQLite reaches the same outcome by a different mechanism than MySQL and Postgres, so passing on one engine says nothing about the others.

- [ ] **Step 1: Write the contention test**

Create `tests/Concurrency/EnrollmentContentionTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Enrollment\EnrollmentRefusalReason;
use Fissible\Vouch\Enrollment\EnrollmentRefused;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

/*
 * DatabaseMigrations, NOT RefreshDatabase — the same reason as
 * AttemptStoreContentionTest. RefreshDatabase wraps each test in a transaction
 * on the default connection, so a second connection cannot see its uncommitted
 * rows and every "racing" writer would operate on an empty table. Every
 * assertion here would pass without anything having raced.
 */
uses(DatabaseMigrations::class);

beforeEach(function (): void {
    $default = Config::string('database.default');
    $settings = Config::array('database.connections.' . $default);

    foreach (['enroll_a', 'enroll_b'] as $name) {
        config(['database.connections.' . $name => $settings]);
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Contention tests need a shared database. In-memory SQLite gives each connection '
            . 'its own, so these would pass without racing. Set VOUCH_SQLITE_PATH to a file, '
            . 'as the CI matrix does.',
        );
    }
});

function guardOn(string $connection, int $wait = 2): EnrollmentGuard
{
    return new EnrollmentGuard(DB::connection($connection), lockWaitSeconds: $wait);
}

function makeCredentialOn(string $connection, string $type = 'password'): void
{
    DB::connection($connection)->table('auth_credentials')->insert([
        'user_id' => 7,
        'type' => $type,
        'secret' => 'digest',
        'strength' => 'knowledge',
        'created_at' => now(),
        'updated_at' => now(),
    ]);
}

it('lets exactly one of two interleaved password enrollments win', function (): void {
    /*
     * A genuine interleave, not two sequential calls. Connection A opens its
     * transaction and holds the lock; B then attempts the same subject. Whether
     * B blocks-then-refuses (MySQL, Postgres) or fails to acquire (SQLite,
     * where lockForUpdate is a no-op and the database-level write lock does the
     * work), the invariant is identical: one active credential.
     */
    $a = DB::connection('enroll_a');
    $refusal = null;

    $a->beginTransaction();

    try {
        $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);
        $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'password')
            ->lockForUpdate()->first();

        try {
            guardOn('enroll_b')->serialize(7, 'password', 1, function (): void {
                makeCredentialOn('enroll_b');
            });
        } catch (EnrollmentRefused $e) {
            $refusal = $e;
        }

        makeCredentialOn('enroll_a');
        $a->commit();
    } catch (\Throwable $e) {
        $a->rollBack();

        throw $e;
    }

    expect($refusal)->toBeInstanceOf(EnrollmentRefused::class)
        ->and(AuthCredential::where('user_id', 7)->where('type', 'password')->whereNull('disabled_at')->count())
        ->toBe(1);
});

it('refuses cleanly rather than surfacing a driver error', function (): void {
    // Without the QueryException -> EnrollmentRefused mapping, "somebody else is
    // enrolling right now" reaches the caller as SQLSTATE noise and becomes
    // indistinguishable from a database outage.
    $a = DB::connection('enroll_a');
    $a->beginTransaction();
    $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'totp']]);
    $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'totp')->lockForUpdate()->first();

    try {
        guardOn('enroll_b')->serialize(7, 'totp', 1, fn (): bool => true);
        $this->fail('Expected EnrollmentRefused.');
    } catch (EnrollmentRefused $refused) {
        expect($refused->reason)->toBe(EnrollmentRefusalReason::Contended);
    } finally {
        $a->rollBack();
    }
});

it('bounds the wait rather than hanging the caller', function (): void {
    /*
     * Engine defaults are wildly inconsistent -- MySQL waits 50s, Postgres waits
     * forever, SQLite fails instantly -- so an unbounded wait would hang a
     * request thread on every contended enrollment. This asserts the bound is
     * actually applied, which no unit test can.
     */
    $a = DB::connection('enroll_a');
    $a->beginTransaction();
    $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);
    $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'password')->lockForUpdate()->first();

    $started = microtime(true);

    try {
        guardOn('enroll_b', wait: 2)->serialize(7, 'password', 1, fn (): bool => true);
    } catch (EnrollmentRefused) {
        // expected
    } finally {
        $a->rollBack();
    }

    expect(microtime(true) - $started)->toBeLessThan(10.0);
});

it('never leaves two recovery-code generations live under interleaved regeneration', function (): void {
    /*
     * The dangerous case, and the one that needs the most care to test honestly.
     *
     * An earlier draft ran the two regenerations SEQUENTIALLY and asserted on the
     * result. That cannot detect the race it describes: gen-a fully commits
     * before gen-b starts, so the test passes with the enrollment lock removed
     * entirely. It measured nothing.
     *
     * It also matters WHERE A's disable half sits. Once A has disabled an
     * existing set, it holds InnoDB row locks on those rows, and B blocks on
     * THOSE regardless of the enrollment lock -- so a seeded fixture would again
     * pass without the lock. The window the enrollment lock uniquely covers is
     * the one with no pre-existing rows: A's disable affects zero rows, takes no
     * row locks, and nothing but the lock row stands between two writers each
     * inserting a full set. That is the same first-enrollment hole spec §2
     * describes for SELECT ... FOR UPDATE, arriving through regeneration.
     *
     * So: no seed, and A's disable runs BEFORE B is invoked. With the lock, B is
     * refused and exactly one generation survives. Without it, B commits ten
     * gen-b rows that A's already-executed disable can no longer catch, A adds
     * ten gen-a rows, and the assertions fail on all three counts -- twenty
     * active, two generations, and no refusal.
     */
    $disableActive = static function (string $connection): void {
        DB::connection($connection)->table('auth_credentials')
            ->where('user_id', 7)->where('type', 'recovery_code')->whereNull('disabled_at')
            ->update(['disabled_at' => now()]);
    };

    $seed = static function (string $connection, string $generation): void {
        $rows = [];

        for ($i = 0; $i < 10; $i++) {
            $rows[] = [
                'user_id' => 7,
                'type' => 'recovery_code',
                'secret' => $generation . '-' . $i,
                'strength' => 'recovery',
                'created_at' => now(),
                'updated_at' => now(),
            ];
        }

        DB::connection($connection)->table('auth_credentials')->insert($rows);
    };

    $a = DB::connection('enroll_a');
    $refusal = null;

    $a->beginTransaction();

    try {
        // A claims and holds the lock for this subject.
        $a->table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'recovery_code']]);
        $a->table('auth_enrollment_locks')->where('user_id', 7)->where('type', 'recovery_code')
            ->lockForUpdate()->first();

        // A's disable half, before B is invoked. Zero rows, so zero row locks.
        $disableActive('enroll_a');

        // B attempts a complete regeneration through the REAL guard.
        try {
            guardOn('enroll_b')->serialize(7, 'recovery_code', 10, static function () use ($disableActive, $seed): void {
                $disableActive('enroll_b');
                $seed('enroll_b', 'gen-b');
            });
        } catch (EnrollmentRefused $e) {
            $refusal = $e;
        }

        // A's create half completes after B's attempt, then A releases.
        $seed('enroll_a', 'gen-a');
        $a->commit();
    } catch (\Throwable $e) {
        $a->rollBack();

        throw $e;
    }

    $active = AuthCredential::where('user_id', 7)
        ->where('type', 'recovery_code')
        ->whereNull('disabled_at')
        ->pluck('secret')
        ->all();

    $generations = array_values(array_unique(array_map(
        static fn (string $secret): string => substr($secret, 0, 5),
        $active,
    )));

    expect($refusal)->toBeInstanceOf(EnrollmentRefused::class)
        ->and($active)->toHaveCount(10)
        ->and($generations)->toBe(['gen-a']);
});

```

- [ ] **Step 2: Run it on file-backed SQLite**

```bash
VOUCH_TEST_DB=sqlite VOUCH_SQLITE_PATH=/tmp/vouch-contention.sqlite vendor/bin/pest tests/Concurrency
```

Note the environment variables are set as a **prefix**, not via `env $VAR`. Zsh does not word-split unquoted variables, and a prior session lost a full matrix run to exactly that mistake — every test "failed" on every engine because of the harness, not the code.

Expected: PASS.

- [ ] **Step 3: Prove the lock is what makes it pass**

```bash
cp src/Enrollment/EnrollmentGuard.php /tmp/eg2.bak
```

Comment out the two statements inside `acquire()`'s `try` block, leaving the method a no-op. Re-run Step 2.

Expected: **both the password test and the recovery-generation test FAIL**, and specifically:

- `lets exactly one of two interleaved password enrollments win` — two active password credentials instead of one, and `$refusal` null.
- `never leaves two recovery-code generations live under interleaved regeneration` — twenty active credentials across two generations, and `$refusal` null.

If either still passes with no locking at all, it is not exercising serialization and must be fixed before proceeding. This is the single most important non-vacuity check in the plan: the spec says outright that the mechanism is unsettled until demonstrated, and a green contention suite over a no-op lock would be the most expensive vacuous control this project has produced.

Restore:

```bash
cp /tmp/eg2.bak src/Enrollment/EnrollmentGuard.php
```

- [ ] **Step 4: Start the two engine containers**

```bash
docker run -d --rm --name vouch-mysql -e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=vouch_test -p 33106:3306 mysql:8
docker run -d --rm --name vouch-pgsql -e POSTGRES_PASSWORD=password -e POSTGRES_DB=vouch_test -p 54106:5432 postgres:16
```

Wait for both to accept connections before running anything — a connection refused during startup looks exactly like a broken configuration:

```bash
until docker exec vouch-mysql mysqladmin ping -ppassword --silent 2>/dev/null; do sleep 2; done; echo "mysql ready"
until docker exec vouch-pgsql pg_isready -U postgres 2>/dev/null; do sleep 2; done; echo "postgres ready"
```

- [ ] **Step 5: Run the FULL suite on MySQL**

Not just the contention file — the amendments, guards, mutations and drivers all touch engine-specific behaviour.

```bash
VOUCH_TEST_DB=mysql DB_HOST=127.0.0.1 DB_PORT=33106 DB_DATABASE=vouch_test DB_USERNAME=root DB_PASSWORD=password vendor/bin/pest
```

Expected: PASS, all tests. Record the exact engine version:

```bash
docker exec vouch-mysql mysql -ppassword -e 'SELECT VERSION();'
```

- [ ] **Step 6: Run the FULL suite on Postgres**

```bash
VOUCH_TEST_DB=pgsql DB_HOST=127.0.0.1 DB_PORT=54106 DB_DATABASE=vouch_test DB_USERNAME=postgres DB_PASSWORD=password vendor/bin/pest
```

Expected: PASS, all tests. Record the version:

```bash
docker exec vouch-pgsql psql -U postgres -t -c 'SELECT version();'
```

- [ ] **Step 7: Run the FULL suite on file-backed SQLite**

```bash
rm -f /tmp/vouch-matrix.sqlite && touch /tmp/vouch-matrix.sqlite
VOUCH_TEST_DB=sqlite VOUCH_SQLITE_PATH=/tmp/vouch-matrix.sqlite vendor/bin/pest
php -r 'echo (new PDO("sqlite:/tmp/vouch-matrix.sqlite"))->query("select sqlite_version()")->fetchColumn(), PHP_EOL;'
```

Expected: PASS, all tests.

**If any leg fails, stop and report it.** Do not mark 2.2 complete with a red leg, and do not skip a test to make a leg green — a skipped contention test is the vacuous control this plan exists to avoid.

- [ ] **Step 8: Tear the containers down**

```bash
docker stop vouch-mysql vouch-pgsql
```

- [ ] **Step 9: Add the enrollment contention job to CI**

In `.github/workflows/ci.yml`, the `database-matrix` job already runs the suite against all three engines. Confirm `tests/Concurrency` is inside its scope — if the job runs `vendor/bin/pest` with no path filter, it already is, and nothing needs changing. If it filters paths, add `tests/Concurrency`.

Also confirm `VOUCH_SQLITE_PATH` in that job points at a **file** and not `:memory:`; the whole contention suite skips itself otherwise, and a skipped suite reports green.

- [ ] **Step 10: Record the verification in `PROJECT.md`**

Update the roadmap: mark Phase 2.2 complete, and add a cross-engine verification record in the same shape 2.1 used — exact commands, exact engine versions, and the date. Include:

- the three commands from Steps 5–7, verbatim
- `mysql:8` / `postgres:16` resolved version strings and the SQLite version
- the Step 3 result: which contention test failed with the lock removed
- the carried-forward open items: passkey (2.2b, gated on evaluating `laravel/passkeys` 0.2.x); password rehash-on-verify as a **security-maintenance limitation**, not an optimisation; typed enrollment and verification DTOs; the recovery-code verification cost of up to ten hash comparisons per attempt, mitigated by 2.3's rate limiting; `FactorFailure::BindingMismatch` as a deliberate extension beyond the spec's five cases

Also note in the session-handoff section that `database-matrix` has still never run in CI — this task proves the local equivalent, which is not the same claim.

- [ ] **Step 11: Final full local gate**

```bash
composer test && composer stan && composer mutate
```

Expected: all three green. `composer mutate` is still scoped to `Fissible\Vouch\Kernel` and this phase changed nothing there, so the floors should be untouched — if the MSI moved, something did reach the kernel and needs investigating rather than a floor adjustment.

- [ ] **Step 12: Commit**

```bash
git add tests/Concurrency/EnrollmentContentionTest.php .github/workflows/ci.yml PROJECT.md
git commit -m "test: prove enrollment serialization on SQLite, MySQL 8 and Postgres 16

Demonstrated failing with the lock removed before being trusted. SQLite
reaches the same invariant by a different mechanism -- lockForUpdate is a
no-op there and the database-level write lock does the work -- which is why
one engine's green says nothing about the others."
```

- [ ] **Step 13: Finish the branch**

Announce: "I'm using the finishing-a-development-branch skill to complete this work."

**REQUIRED SUB-SKILL:** `superpowers:finishing-a-development-branch`, with base branch `main`.

---

## Self-review

Run against the spec after the plan was complete.

**Spec coverage.** Every section maps to a task: §1 dependencies → Task 1; §2 contract and value objects → Task 7, with `maxActiveCredentials` enforcement in Task 6 and `OneTimeSecret` in Task 1; §3 store-owned mutations and the three rejection rules → Task 5; §4 Amendments A/B/C/D → Tasks 2, 3, 4, 5; §5 the five drivers → Tasks 8, 9, 10; §6 testing → distributed, with the contention matrix as Task 12; §7 out-of-scope items → recorded in Task 12's `PROJECT.md` update rather than implemented; §8 decision log → reflected in code comments at each decision point.

**Three gaps found and closed while reviewing.**

1. The spec says enrollment "upserts the `(user_id, type)` row." Verified against real engines, `upsert()` with an empty update array compiles to a plain `INSERT` and throws on the second call. The plan specifies `insertOrIgnore()` and records why in the verified-facts table. Following the spec literally would have produced a guard that fails on every enrollment after the first.

2. The spec's TOTP driver would naturally be written with otphp's `$leeway` parameter. That returns `bool` and hides which timestep matched, making Amendment B unimplementable. The plan forbids it explicitly and specifies candidate-step iteration.

3. `FactorFailure` gains a sixth case, `BindingMismatch`, beyond the spec's five. Flagged in Task 7's preamble and in Task 12's carry-forward list so it reaches the reviewer as a choice.

**Type consistency.** `EnrollmentResult` exposes `$secrets` (not `$oneTimeSecrets`) throughout. `FactorResult::satisfied()` is variadic in mutations everywhere it appears. `AttemptStore::transition()` is variadic from Task 5 onward, and Task 5 updates the two existing test files that used the old third parameter. `Verdict` is accessed as a property, `$verdict->satisfied`, verified against `src/Kernel/Satisfiability/Verdict.php`. `EnrollmentGuard::serialize()` has the same four-parameter signature in Tasks 6, 8, 9, 10 and 12.

**No placeholders.** Every code step carries the actual code. Every non-vacuity probe names the specific test that must fail and the specific edit that must cause it.

**One thing the plan cannot prove.** Task 10 Step 10 item 3 asks the implementer to confirm that reordering challenge-creation and delivery breaks nothing observable — because it genuinely does not, from outside. The ordering matters (a delivered code with no row to verify it against locks a user out of a factor they hold) but is not testable through the public surface, so it is a code comment and a note in the report rather than an assertion. Recorded here so the reviewer sees it was considered rather than missed.
