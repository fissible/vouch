# Vouch Phase 2.1 — Persistence Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the data layer for the vouch Laravel package — ten tables, ten Eloquent models, three contracts — plus a database-backed authentication-attempt store whose concurrency safety is proven against SQLite, MySQL, and Postgres.

**Architecture:** Phase 1 shipped `Fissible\Vouch\Kernel`, a framework-free decision engine. This phase adds Laravel to the same package under sibling namespaces, leaving the kernel untouched and still boundary-enforced. The attempt store splits responsibility deliberately: the kernel's `TransitionRules` decides whether a transition is *legal*, and the store decides whether the caller *won the race*, via compare-and-swap on a monotonic version column. Nothing here authenticates anyone; 2.1 is the substrate 2.2–2.4 build on.

**Tech Stack:** PHP 8.4, Laravel 13 (`illuminate/*` ^13.0), Orchestra Testbench ^11.0, Pest 3, PHPStan level 9.

## Global Constraints

- **PHP `^8.4`.** No lower floor.
- **`Fissible\Vouch\Kernel` may depend only on `php` and `psr/clock`.** Adding `illuminate/*` to the package does NOT relax this. The regex boundary scans in `tests/Arch/KernelBoundaryTest.php` are the enforcement and must stay green.
- **Namespace root `Fissible\Vouch\` → `src/`**, tests `Fissible\Vouch\Tests\` → `tests/`. New Phase 2 code lives in sibling directories to `src/Kernel/` — never inside it.
- **`declare(strict_types=1);` in every PHP file.**
- **PHPStan level 9 over `src` and `tests` must stay clean.**
- **Mutation floors unchanged:** `mutate:msi --min=80`, `mutate:covered --min=95`. Do not lower either. Mutation testing remains scoped to `--class="Fissible\Vouch\Kernel"`; Phase 2 code is out of its scope by design.
- **All vouch timestamps are stored in UTC.**
- **Secret material uses Laravel's `encrypted` cast** (parent spec §7.6). Never plaintext.
- **Conventional Commits.** Commit by explicit path, never `git add -A` — `.superpowers/`, `vendor/`, `build/`, `.serena/` are gitignored.
- Model class names are `Auth`-prefixed and mirror table names exactly (`AuthIdentifier` ↔ `auth_identifiers`), avoiding collisions with Laravel's own `Session` and `Policy` concepts at call sites.

---

## File Structure

| File | Responsibility |
|---|---|
| `composer.json` | Adds `illuminate/*` ^13.0, `orchestra/testbench` ^11.0, Laravel auto-discovery |
| `config/vouch.php` | User model, attempt TTL, recovery-grace TTL, revocation retention |
| `src/VouchServiceProvider.php` | Config merge/publish, migration loading, contract bindings, command registration |
| `src/Contracts/TenantResolver.php` | Tenant seam — Station adapts, Sluice uses the null implementation |
| `src/Contracts/AuditSink.php` | Audit seam — drivers ship in 2.4 |
| `src/Contracts/AttemptStore.php` | Attempt-store seam — Redis driver additive later |
| `src/Tenancy/NullTenantResolver.php` | Single-tenant default |
| `src/Sessions/SessionBinding.php` | HMAC-SHA256 of host session ID keyed to `APP_KEY` |
| `src/Sessions/RevokedReason.php` | Backed enum, six constrained values |
| `src/Attempts/DatabaseAttemptStore.php` | CAS transitions, all-or-nothing consume-and-advance |
| `src/Attempts/TransitionOutcome.php` | Typed result of a transition attempt |
| `src/Models/Auth*.php` | Ten Eloquent models |
| `database/migrations/*.php` | Ten anonymous-class migrations |
| `src/Console/VouchPruneCommand.php` | Housekeeping sweep for expired and long-revoked rows |
| `tests/TestCase.php` | Testbench base; selects DB connection from environment |
| `tests/Concurrency/*.php` | The adversarial matrix — runs on all three engines |

---

## Task 1: Laravel package scaffolding and the multi-engine test harness

**Files:**
- Modify: `composer.json`
- Create: `config/vouch.php`, `src/VouchServiceProvider.php`, `tests/TestCase.php`
- Modify: `phpunit.xml.dist`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing
- Produces: `Fissible\Vouch\VouchServiceProvider`; `Fissible\Vouch\Tests\TestCase` (Testbench base, connection selected by the `DB_CONNECTION` env var); `config('vouch.*')`

- [ ] **Step 1: Add Laravel dependencies to `composer.json`**

In `require`, after `"psr/clock"`:

```json
        "illuminate/console": "^13.0",
        "illuminate/database": "^13.0",
        "illuminate/support": "^13.0"
```

In `require-dev`, add:

```json
        "orchestra/testbench": "^11.0"
```

Add a top-level `extra` block for auto-discovery:

```json
    "extra": {
        "laravel": {
            "providers": [
                "Fissible\\Vouch\\VouchServiceProvider"
            ]
        }
    },
```

Run `composer update illuminate/console illuminate/database illuminate/support orchestra/testbench --with-all-dependencies`.

- [ ] **Step 2: Prove the kernel boundary test now guards something real**

Until now `Illuminate` was not installed, so the framework ban had nothing to catch. Verify it does now. Temporarily create `src/Kernel/_Probe.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel;

use Illuminate\Support\Str;

final class _Probe
{
    public function slug(string $v): string
    {
        return Str::slug($v);
    }
}
```

Run: `vendor/bin/pest tests/Arch/KernelBoundaryTest.php`
Expected: FAIL, naming `_Probe.php` and the `Illuminate` namespace.

Delete `src/Kernel/_Probe.php`. Re-run; expected PASS. Record both outputs in your report — this is the first moment that ban has been falsifiable.

- [ ] **Step 3: Write `config/vouch.php`**

```php
<?php

declare(strict_types=1);

return [
    /*
     * The application's authenticatable model. Vouch's foreign keys target
     * whatever this resolves to, so a host with a non-standard user model does
     * not need to edit migrations.
     */
    'user_model' => env('VOUCH_USER_MODEL', 'App\\Models\\User'),

    'attempts' => [
        // How long an in-progress authentication attempt stays valid.
        'ttl_seconds' => (int) env('VOUCH_ATTEMPT_TTL', 600),
    ],

    'recovery_grace' => [
        /*
         * Absolute lifetime of a recovery-grace session, from creation.
         * Never extended by activity (design §2, Expiry).
         */
        'ttl_seconds' => (int) env('VOUCH_RECOVERY_GRACE_TTL', 900),
    ],

    'sessions' => [
        // How long revoked session rows are retained before the sweep deletes them.
        'revocation_retention_days' => (int) env('VOUCH_REVOCATION_RETENTION_DAYS', 30),
    ],
];
```

- [ ] **Step 4: Write the service provider**

Create `src/VouchServiceProvider.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch;

use Illuminate\Support\ServiceProvider;

final class VouchServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/vouch.php', 'vouch');
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/vouch.php' => $this->app->configPath('vouch.php'),
            ], 'vouch-config');

            $this->publishes([
                __DIR__ . '/../database/migrations' => $this->app->databasePath('migrations'),
            ], 'vouch-migrations');
        }
    }
}
```

- [ ] **Step 5: Write the Testbench base case**

Create `tests/TestCase.php`. The connection is chosen by environment so one suite runs on three engines.

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests;

use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /**
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [VouchServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $connection = (string) (getenv('VOUCH_TEST_DB') ?: 'sqlite');

        $app['config']->set('database.default', $connection);
        $app['config']->set('app.timezone', 'UTC');

        match ($connection) {
            'sqlite' => $app['config']->set('database.connections.sqlite', [
                'driver' => 'sqlite',
                'database' => getenv('VOUCH_SQLITE_PATH') ?: ':memory:',
                'prefix' => '',
                'foreign_key_constraints' => true,
            ]),
            'mysql' => $app['config']->set('database.connections.mysql', [
                'driver' => 'mysql',
                'host' => getenv('DB_HOST') ?: '127.0.0.1',
                'port' => getenv('DB_PORT') ?: '3306',
                'database' => getenv('DB_DATABASE') ?: 'vouch_test',
                'username' => getenv('DB_USERNAME') ?: 'root',
                'password' => getenv('DB_PASSWORD') ?: 'password',
                'charset' => 'utf8mb4',
                'prefix' => '',
            ]),
            'pgsql' => $app['config']->set('database.connections.pgsql', [
                'driver' => 'pgsql',
                'host' => getenv('DB_HOST') ?: '127.0.0.1',
                'port' => getenv('DB_PORT') ?: '5432',
                'database' => getenv('DB_DATABASE') ?: 'vouch_test',
                'username' => getenv('DB_USERNAME') ?: 'postgres',
                'password' => getenv('DB_PASSWORD') ?: 'password',
                'charset' => 'utf8',
                'prefix' => '',
            ]),
            default => throw new \InvalidArgumentException(
                sprintf('Unsupported VOUCH_TEST_DB value: %s', $connection),
            ),
        };
    }
}
```

- [ ] **Step 6: Point Pest at the base case for database tests**

Append to `tests/Pest.php`:

```php
uses(\Fissible\Vouch\Tests\TestCase::class)->in('Database', 'Concurrency');
```

Kernel and Arch tests stay plain Pest with no framework boot — they must not become slower or framework-dependent.

- [ ] **Step 7: Write a smoke test proving the package boots**

Create `tests/Database/ServiceProviderTest.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;

it('boots the service provider and merges config', function (): void {
    expect(config('vouch.recovery_grace.ttl_seconds'))->toBe(900)
        ->and(config('vouch.attempts.ttl_seconds'))->toBe(600);
});

it('connects to the configured test database', function (): void {
    expect(DB::connection()->getPdo())->not->toBeNull();
});
```

- [ ] **Step 8: Run the suite**

Run: `composer test`
Expected: PASS. Kernel and arch tests unchanged; two new database tests pass on SQLite.

Run: `composer stan`
Expected: no errors. If PHPStan cannot resolve Testbench's untyped `$app` parameters, add the narrowest possible `@param` annotations to `getPackageProviders()` and `defineEnvironment()` naming `Application` — do not add `ignoreErrors` and do not lower the level.

- [ ] **Step 9: Add the database matrix to CI**

In `.github/workflows/ci.yml`, add a new job after `mutation`:

```yaml
  database-matrix:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        db: [sqlite, mysql, pgsql]

    services:
      mysql:
        image: mysql:8
        env:
          MYSQL_ROOT_PASSWORD: password
          MYSQL_DATABASE: vouch_test
        ports: ['3306:3306']
        options: >-
          --health-cmd="mysqladmin ping -ppassword"
          --health-interval=10s --health-timeout=5s --health-retries=10
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: password
          POSTGRES_DB: vouch_test
        ports: ['5432:5432']
        options: >-
          --health-cmd=pg_isready
          --health-interval=10s --health-timeout=5s --health-retries=10

    steps:
      - uses: actions/checkout@v5

      - name: Set up PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          extensions: json, mbstring, pdo_sqlite, pdo_mysql, pdo_pgsql
          coverage: none

      - name: Install
        run: composer install --prefer-dist --no-progress

      - name: Database suite
        env:
          VOUCH_TEST_DB: ${{ matrix.db }}
          DB_HOST: 127.0.0.1
          DB_DATABASE: vouch_test
          DB_PASSWORD: password
          DB_USERNAME: ${{ matrix.db == 'mysql' && 'root' || 'postgres' }}
          DB_PORT: ${{ matrix.db == 'mysql' && '3306' || '5432' }}
          VOUCH_SQLITE_PATH: ${{ runner.temp }}/vouch-matrix.sqlite
        run: vendor/bin/pest tests/Database tests/Concurrency
```

Add `database-matrix` to the `validate` job's `needs:` list so branch protection covers it.

**Note the SQLite path.** The matrix uses a *file*, never `:memory:`. Each connection to an in-memory SQLite database gets its own private database, so concurrency tests against `:memory:` cannot race and would pass unconditionally — the exact class of vacuous control this project has found five times. The normal suite keeps `:memory:` for speed; the matrix uses a file.

- [ ] **Step 10: Commit**

```bash
git add composer.json composer.lock config/vouch.php src/VouchServiceProvider.php \
        tests/TestCase.php tests/Pest.php tests/Database/ServiceProviderTest.php \
        .github/workflows/ci.yml
git commit -m "feat: add Laravel package scaffolding and multi-engine test harness"
```

---

## Task 2: Tenancy and audit contracts

**Files:**
- Create: `src/Contracts/TenantResolver.php`, `src/Contracts/AuditSink.php`, `src/Tenancy/NullTenantResolver.php`
- Test: `tests/Database/TenancyTest.php`

**Interfaces:**
- Consumes: nothing
- Produces: `TenantResolver::currentTenantId(): ?string`; `AuditSink::record(string $event, array $context): void`; `NullTenantResolver` bound as the default `TenantResolver`

- [ ] **Step 1: Write the failing test**

Create `tests/Database/TenancyTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Tenancy\NullTenantResolver;

it('resolves the null tenant resolver by default', function (): void {
    expect(app(TenantResolver::class))->toBeInstanceOf(NullTenantResolver::class);
});

it('reports no tenant in a single-tenant application', function (): void {
    expect(app(TenantResolver::class)->currentTenantId())->toBeNull();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `vendor/bin/pest tests/Database/TenancyTest.php`
Expected: FAIL — `Target class [Fissible\Vouch\Contracts\TenantResolver] does not exist.`

- [ ] **Step 3: Write the contracts**

Create `src/Contracts/TenantResolver.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

/**
 * Resolves the tenant for the current request.
 *
 * Vouch never references a host application's tenant model. Station binds an
 * adapter over its own TenantContext; single-tenant hosts use NullTenantResolver.
 */
interface TenantResolver
{
    /**
     * The current tenant's identifier, or null in a single-tenant application.
     */
    public function currentTenantId(): ?string;
}
```

Create `src/Contracts/AuditSink.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

/**
 * Receives security-relevant events.
 *
 * Implementations ship in Phase 2.4 (activitylog, attest, null). Credential
 * material must never reach a sink — parent spec §7.6 requires a tested
 * redaction pass, which lives with the drivers.
 */
interface AuditSink
{
    /**
     * @param array<string, scalar|null> $context
     */
    public function record(string $event, array $context): void;
}
```

Create `src/Tenancy/NullTenantResolver.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tenancy;

use Fissible\Vouch\Contracts\TenantResolver;

final class NullTenantResolver implements TenantResolver
{
    public function currentTenantId(): ?string
    {
        return null;
    }
}
```

- [ ] **Step 4: Bind the default in the service provider**

In `src/VouchServiceProvider.php`, add to `register()` after the `mergeConfigFrom` call:

```php
        $this->app->bind(
            \Fissible\Vouch\Contracts\TenantResolver::class,
            \Fissible\Vouch\Tenancy\NullTenantResolver::class,
        );
```

`AuditSink` is deliberately left unbound: 2.4 ships the drivers, and a host that resolves it before then should get a clear container error rather than a silent no-op that discards audit events.

- [ ] **Step 5: Run to verify it passes**

Run: `composer test && composer stan`
Expected: PASS, no PHPStan errors.

- [ ] **Step 6: Commit**

```bash
git add src/Contracts src/Tenancy src/VouchServiceProvider.php tests/Database/TenancyTest.php
git commit -m "feat: add tenancy and audit contracts"
```

---

## Task 3: Identifiers and credentials

**Files:**
- Create: `database/migrations/2026_08_12_000001_create_auth_identifiers_table.php`, `database/migrations/2026_08_12_000002_create_auth_credentials_table.php`
- Create: `src/Models/AuthIdentifier.php`, `src/Models/AuthCredential.php`
- Test: `tests/Database/IdentifiersAndCredentialsTest.php`

**Interfaces:**
- Consumes: `config('vouch.user_model')` (Task 1)
- Produces: `AuthIdentifier` (`user_id`, `type`, `value`, `verified_at`, `is_primary`); `AuthCredential` (`user_id`, `type`, `relying_party_id`, `secret`, `strength`, `is_multi_factor`, `user_verified`, `phishing_resistant`, `authenticator_id`, `last_used_at`, `disabled_at`)

- [ ] **Step 1: Write the failing test**

Create `tests/Database/IdentifiersAndCredentialsTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('stores an identifier and round-trips its columns', function (): void {
    $identifier = AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada@example.com',
        'is_primary' => true,
    ]);

    $fresh = AuthIdentifier::findOrFail($identifier->getKey());

    expect($fresh->type)->toBe('email')
        ->and($fresh->value)->toBe('ada@example.com')
        ->and($fresh->is_primary)->toBeTrue()
        ->and($fresh->verified_at)->toBeNull();
});

it('rejects a duplicate identifier of the same type and value', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'ada@example.com']);

    AuthIdentifier::create(['user_id' => 2, 'type' => 'email', 'value' => 'ada@example.com']);
})->throws(\Illuminate\Database\QueryException::class);

it('permits the same value under different identifier types', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'ada']);
    AuthIdentifier::create(['user_id' => 1, 'type' => 'username', 'value' => 'ada']);

    expect(AuthIdentifier::count())->toBe(2);
});

it('encrypts credential secrets at rest', function (): void {
    $credential = AuthCredential::create([
        'user_id' => 1,
        'type' => 'totp',
        'secret' => 'JBSWY3DPEHPK3PXP',
        'strength' => 'possession',
    ]);

    $raw = DB::table('auth_credentials')->where('id', $credential->getKey())->value('secret');

    expect($raw)->not->toBe('JBSWY3DPEHPK3PXP')
        ->and(AuthCredential::findOrFail($credential->getKey())->secret)->toBe('JBSWY3DPEHPK3PXP');
});

it('defaults the §3.6 satisfiability attributes to the safe value', function (): void {
    $credential = AuthCredential::create([
        'user_id' => 1,
        'type' => 'password',
        'secret' => 'hash',
        'strength' => 'knowledge',
    ]);

    $fresh = AuthCredential::findOrFail($credential->getKey());

    expect($fresh->is_multi_factor)->toBeFalse()
        ->and($fresh->user_verified)->toBeFalse()
        ->and($fresh->phishing_resistant)->toBeFalse()
        ->and($fresh->relying_party_id)->toBeNull()
        ->and($fresh->authenticator_id)->toBeNull()
        ->and($fresh->disabled_at)->toBeNull();
});
```

The defaults test matters: every one of those booleans defaulting to `false` is the fail-closed direction. A credential that defaults to `phishing_resistant = true` would satisfy a high-assurance policy it should not.

- [ ] **Step 2: Run to verify it fails**

Run: `vendor/bin/pest tests/Database/IdentifiersAndCredentialsTest.php`
Expected: FAIL — `Class "Fissible\Vouch\Models\AuthIdentifier" not found`.

- [ ] **Step 3: Write the identifiers migration**

Create `database/migrations/2026_08_12_000001_create_auth_identifiers_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_identifiers', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id')->index();
            $table->string('type', 32);
            $table->string('value', 255);
            $table->timestamp('verified_at')->nullable();
            $table->boolean('is_primary')->default(false);
            $table->timestamps();

            $table->unique(['type', 'value']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_identifiers');
    }
};
```

- [ ] **Step 4: Write the credentials migration**

Create `database/migrations/2026_08_12_000002_create_auth_credentials_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_credentials', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id')->index();

            // Open string, not an enum: drivers register their own type keys in 2.2.
            $table->string('type', 32);

            // WebAuthn origin binding (parent spec §4.1). Null for origin-free
            // credentials such as passwords and TOTP secrets.
            $table->string('relying_party_id', 255)->nullable();

            $table->text('secret')->nullable();
            $table->string('strength', 32);

            // §3.6 satisfiability attributes. Every one defaults false — the
            // fail-closed direction.
            $table->boolean('is_multi_factor')->default(false);
            $table->boolean('user_verified')->default(false);
            $table->boolean('phishing_resistant')->default(false);
            $table->string('authenticator_id', 255)->nullable();

            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('disabled_at')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'type']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_credentials');
    }
};
```

- [ ] **Step 5: Write the models**

Create `src/Models/AuthIdentifier.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;

final class AuthIdentifier extends Model
{
    protected $table = 'auth_identifiers';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'verified_at' => 'datetime',
            'is_primary' => 'boolean',
        ];
    }
}
```

Create `src/Models/AuthCredential.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;

final class AuthCredential extends Model
{
    protected $table = 'auth_credentials';

    protected $guarded = [];

    protected $hidden = ['secret'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'secret' => 'encrypted',
            'is_multi_factor' => 'boolean',
            'user_verified' => 'boolean',
            'phishing_resistant' => 'boolean',
            'last_used_at' => 'datetime',
            'disabled_at' => 'datetime',
        ];
    }
}
```

`$hidden` keeps the secret out of any accidental `toArray()` or JSON serialisation — a log line or an API response that includes a TOTP seed is a credential disclosure.

- [ ] **Step 6: Run to verify it passes**

Run: `composer test && composer stan`
Expected: PASS (5 new tests), no PHPStan errors.

- [ ] **Step 7: Commit**

```bash
git add database/migrations/2026_08_12_00000{1,2}_* src/Models/AuthIdentifier.php \
        src/Models/AuthCredential.php tests/Database/IdentifiersAndCredentialsTest.php
git commit -m "feat: add identifier and credential tables and models"
```

---

## Task 4: Connections, federated identities, and link requests

**Files:**
- Create: three migrations `2026_08_12_000003`–`000005`, `src/Models/AuthConnection.php`, `src/Models/AuthFederatedIdentity.php`, `src/Models/AuthLinkRequest.php`
- Test: `tests/Database/FederationTest.php`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces: `AuthConnection` (`tenant_id`, `email_domain`, `discovery_url`, `client_id`, `client_secret`, `claim_mappings`, `jit_rules`, `trust_email_verified`, `auto_link`); `AuthFederatedIdentity` (`connection_id`, `issuer`, `subject`, `claims`, `user_id`); `AuthLinkRequest` (`user_id`, `federated_identity_id`, `proven_at`, `expires_at`)

- [ ] **Step 1: Write the failing test**

Create `tests/Database/FederationTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthConnection;
use Fissible\Vouch\Models\AuthFederatedIdentity;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function oidcConnection(string $tenant = 'acme'): AuthConnection
{
    return AuthConnection::create([
        'tenant_id' => $tenant,
        'email_domain' => $tenant . '.example',
        'discovery_url' => 'https://idp.' . $tenant . '.example/.well-known/openid-configuration',
        'client_id' => 'client-' . $tenant,
        'client_secret' => 'secret-' . $tenant,
    ]);
}

it('encrypts the connection client secret at rest', function (): void {
    $conn = oidcConnection();

    $raw = DB::table('auth_connections')->where('id', $conn->getKey())->value('client_secret');

    expect($raw)->not->toBe('secret-acme')
        ->and(AuthConnection::findOrFail($conn->getKey())->client_secret)->toBe('secret-acme');
});

it('defaults claim trust and auto-link to the safe value', function (): void {
    $conn = AuthConnection::findOrFail(oidcConnection()->getKey());

    expect($conn->trust_email_verified)->toBeFalse()
        ->and($conn->auto_link)->toBeFalse();
});

it('enforces uniqueness on connection, issuer and subject', function (): void {
    $conn = oidcConnection();

    AuthFederatedIdentity::create([
        'connection_id' => $conn->getKey(),
        'issuer' => 'https://idp.acme.example',
        'subject' => 'sub-1',
        'user_id' => 1,
    ]);

    AuthFederatedIdentity::create([
        'connection_id' => $conn->getKey(),
        'issuer' => 'https://idp.acme.example',
        'subject' => 'sub-1',
        'user_id' => 2,
    ]);
})->throws(\Illuminate\Database\QueryException::class);

it('permits the same issuer and subject under a different connection', function (): void {
    $acme = oidcConnection('acme');
    $beta = oidcConnection('beta');

    foreach ([$acme, $beta] as $conn) {
        AuthFederatedIdentity::create([
            'connection_id' => $conn->getKey(),
            'issuer' => 'https://shared-idp.example',
            'subject' => 'sub-1',
            'user_id' => 1,
        ]);
    }

    expect(AuthFederatedIdentity::count())->toBe(2);
});

it('refuses a federated identity with no connection', function (): void {
    AuthFederatedIdentity::create([
        'connection_id' => null,
        'issuer' => 'https://idp.acme.example',
        'subject' => 'sub-1',
        'user_id' => 1,
    ]);
})->throws(\Illuminate\Database\QueryException::class);
```

The last two tests are the cross-tenant takeover guard from parent spec §7.2 rule 1, expressed as database constraints rather than driver convention. A shared public IdP must be able to issue the same subject to two different tenants without them colliding — and a federated identity must never exist untethered from a connection.

- [ ] **Step 2: Run to verify it fails**

Run: `vendor/bin/pest tests/Database/FederationTest.php`
Expected: FAIL — `Class "Fissible\Vouch\Models\AuthConnection" not found`.

- [ ] **Step 3: Write the connections migration**

Create `database/migrations/2026_08_12_000003_create_auth_connections_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_connections', function (Blueprint $table): void {
            $table->id();
            $table->string('tenant_id', 255)->nullable()->index();
            $table->string('email_domain', 255)->nullable()->index();
            $table->string('discovery_url', 512)->nullable();
            $table->string('client_id', 255)->nullable();
            $table->text('client_secret')->nullable();
            $table->json('claim_mappings')->nullable();
            $table->json('jit_rules')->nullable();

            // Both default false — parent spec §7.2 rules 2 and 3 require
            // per-connection opt-in, never a default-on trust.
            $table->boolean('trust_email_verified')->default(false);
            $table->boolean('auto_link')->default(false);

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_connections');
    }
};
```

- [ ] **Step 4: Write the federated identities migration**

Create `database/migrations/2026_08_12_000004_create_auth_federated_identities_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_federated_identities', function (Blueprint $table): void {
            $table->id();

            // NOT NULL by design: a federated identity untethered from a
            // connection would be usable across tenants (parent spec §7.2).
            $table->foreignId('connection_id')
                ->constrained('auth_connections')
                ->cascadeOnDelete();

            $table->string('issuer', 512);
            $table->string('subject', 255);
            $table->json('claims')->nullable();
            $table->unsignedBigInteger('user_id')->nullable()->index();
            $table->timestamps();

            // The identity key is (connection, issuer, subject) — never email.
            $table->unique(['connection_id', 'issuer', 'subject'], 'auth_fedid_conn_iss_sub_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_federated_identities');
    }
};
```

The index name is given explicitly because the generated name would exceed MySQL's 64-character identifier limit.

- [ ] **Step 5: Write the link requests migration**

Create `database/migrations/2026_08_12_000005_create_auth_link_requests_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_link_requests', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id')->index();
            $table->foreignId('federated_identity_id')
                ->constrained('auth_federated_identities')
                ->cascadeOnDelete();
            $table->timestamp('proven_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_link_requests');
    }
};
```

- [ ] **Step 6: Write the three models**

Create `src/Models/AuthConnection.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;

final class AuthConnection extends Model
{
    protected $table = 'auth_connections';

    protected $guarded = [];

    protected $hidden = ['client_secret'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'client_secret' => 'encrypted',
            'claim_mappings' => 'array',
            'jit_rules' => 'array',
            'trust_email_verified' => 'boolean',
            'auto_link' => 'boolean',
        ];
    }
}
```

Create `src/Models/AuthFederatedIdentity.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;

final class AuthFederatedIdentity extends Model
{
    protected $table = 'auth_federated_identities';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['claims' => 'array'];
    }
}
```

Create `src/Models/AuthLinkRequest.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;

final class AuthLinkRequest extends Model
{
    protected $table = 'auth_link_requests';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'proven_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}
```

- [ ] **Step 7: Run to verify it passes**

Run: `composer test && composer stan`
Expected: PASS (5 new tests), no PHPStan errors.

If the not-null test fails on SQLite because foreign-key enforcement is off, confirm `foreign_key_constraints => true` is set in `tests/TestCase.php` (Task 1 Step 5). Do not weaken the test.

- [ ] **Step 8: Commit**

```bash
git add database/migrations/2026_08_12_00000{3,4,5}_* src/Models/AuthConnection.php \
        src/Models/AuthFederatedIdentity.php src/Models/AuthLinkRequest.php \
        tests/Database/FederationTest.php
git commit -m "feat: add federation tables with cross-tenant uniqueness constraints"
```

---

## Task 5: Policies and token assurances

**Files:**
- Create: `database/migrations/2026_08_12_000006_create_auth_policies_table.php`, `database/migrations/2026_08_12_000007_create_auth_token_assurances_table.php`
- Create: `src/Models/AuthPolicy.php`, `src/Models/AuthTokenAssurance.php`
- Test: `tests/Database/PoliciesAndTokenAssurancesTest.php`

**Interfaces:**
- Consumes: `Fissible\Vouch\Kernel\Enumeration\EnumerationPosture`, `Fissible\Vouch\Kernel\Policy\PolicyParser` (Phase 1)
- Produces: `AuthPolicy` (`tenant_id`, `scope`, `document`, `posture`); `AuthTokenAssurance` (`token_id`, `acr`, `amr`, `credential_ids`, `issuing_session_id`, `issued_at`)

- [ ] **Step 1: Write the failing test**

Create `tests/Database/PoliciesAndTokenAssurancesTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\PolicyParser;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthTokenAssurance;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('round-trips a policy document the kernel parser accepts', function (): void {
    $document = ['all_of' => ['password', 'totp']];

    $policy = AuthPolicy::create([
        'tenant_id' => 'acme',
        'scope' => 'login',
        'document' => $document,
        'posture' => 'strict',
    ]);

    $fresh = AuthPolicy::findOrFail($policy->getKey());

    expect($fresh->document)->toBe($document)
        ->and($fresh->posture)->toBe('strict');

    $parsed = (new PolicyParser())->parse($fresh->document);
    expect($parsed)->toBeInstanceOf(AllOf::class);
});

it('stores an amr list and credential ids as arrays', function (): void {
    $assurance = AuthTokenAssurance::create([
        'token_id' => 42,
        'acr' => 'aal2',
        'amr' => ['password', 'totp'],
        'credential_ids' => [7, 9],
        'issuing_session_id' => 'sess-1',
        'issued_at' => now(),
    ]);

    $fresh = AuthTokenAssurance::findOrFail($assurance->getKey());

    expect($fresh->amr)->toBe(['password', 'totp'])
        ->and($fresh->credential_ids)->toBe([7, 9])
        ->and($fresh->acr)->toBe('aal2');
});

it('allows only one assurance record per token', function (): void {
    $attributes = [
        'token_id' => 42,
        'acr' => 'aal2',
        'amr' => ['password'],
        'credential_ids' => [7],
        'issuing_session_id' => 'sess-1',
        'issued_at' => now(),
    ];

    AuthTokenAssurance::create($attributes);
    AuthTokenAssurance::create($attributes);
})->throws(\Illuminate\Database\QueryException::class);
```

The round-trip through `PolicyParser` matters: it proves the stored JSON shape is one the Phase 1 kernel actually accepts, rather than a shape that only looks right.

- [ ] **Step 2: Run to verify it fails**

Run: `vendor/bin/pest tests/Database/PoliciesAndTokenAssurancesTest.php`
Expected: FAIL — `Class "Fissible\Vouch\Models\AuthPolicy" not found`.

- [ ] **Step 3: Write the policies migration**

Create `database/migrations/2026_08_12_000006_create_auth_policies_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_policies', function (Blueprint $table): void {
            $table->id();
            $table->string('tenant_id', 255)->nullable()->index();

            // Which intent this policy governs: login, step_up, enroll_factor, recover.
            $table->string('scope', 32);

            $table->json('document');
            $table->string('posture', 16)->default('friendly');
            $table->timestamps();

            $table->unique(['tenant_id', 'scope']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_policies');
    }
};
```

- [ ] **Step 4: Write the token assurances migration**

Create `database/migrations/2026_08_12_000007_create_auth_token_assurances_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_token_assurances', function (Blueprint $table): void {
            $table->id();

            /*
             * References personal_access_tokens.id. Declared as a plain indexed
             * column rather than a foreign key because Sanctum's table may not
             * exist when vouch migrates, and vouch does not own its schema.
             * Phase 2.4 adds the cascade-delete behaviour in application code.
             */
            $table->unsignedBigInteger('token_id')->unique();

            $table->string('acr', 64);
            $table->json('amr');
            $table->json('credential_ids');
            $table->string('issuing_session_id', 255)->index();
            $table->timestamp('issued_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_token_assurances');
    }
};
```

- [ ] **Step 5: Write the models**

Create `src/Models/AuthPolicy.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;

final class AuthPolicy extends Model
{
    protected $table = 'auth_policies';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['document' => 'array'];
    }
}
```

Create `src/Models/AuthTokenAssurance.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;

final class AuthTokenAssurance extends Model
{
    protected $table = 'auth_token_assurances';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'amr' => 'array',
            'credential_ids' => 'array',
            'issued_at' => 'datetime',
        ];
    }
}
```

- [ ] **Step 6: Run to verify it passes**

Run: `composer test && composer stan`
Expected: PASS (3 new tests), no PHPStan errors.

- [ ] **Step 7: Commit**

```bash
git add database/migrations/2026_08_12_00000{6,7}_* src/Models/AuthPolicy.php \
        src/Models/AuthTokenAssurance.php tests/Database/PoliciesAndTokenAssurancesTest.php
git commit -m "feat: add policy and token-assurance tables and models"
```

---

## Task 6: Sessions, HMAC binding, and revocation

**Files:**
- Create: `database/migrations/2026_08_12_000008_create_auth_sessions_table.php`
- Create: `src/Models/AuthSession.php`, `src/Sessions/SessionBinding.php`, `src/Sessions/RevokedReason.php`
- Test: `tests/Database/SessionsTest.php`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces: `SessionBinding::for(string $hostSessionId): string`; `RevokedReason` (backed enum: `Logout`, `GraceExpired`, `CredentialChanged`, `PasswordChanged`, `AdminRevoked`, `Superseded`); `AuthSession` (`session_binding`, `user_id`, `amr`, `acr`, `assurance_facts`, `recovery_grace_expires_at`, `revoked_at`, `revoked_reason`, `last_factor_at`)

- [ ] **Step 1: Write the failing test**

Create `tests/Database/SessionsTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('never stores the raw host session id', function (): void {
    $hostSessionId = 'the-raw-bearer-session-id';

    $binding = SessionBinding::for($hostSessionId);

    expect($binding)->not->toContain($hostSessionId)
        ->and($binding)->toHaveLength(64);
});

it('produces a stable binding for the same session id', function (): void {
    expect(SessionBinding::for('abc'))->toBe(SessionBinding::for('abc'));
});

it('produces different bindings for different session ids', function (): void {
    expect(SessionBinding::for('abc'))->not->toBe(SessionBinding::for('abd'));
});

it('produces a different binding when APP_KEY changes', function (): void {
    $before = SessionBinding::for('abc');

    config(['app.key' => 'base64:' . base64_encode(random_bytes(32))]);

    expect(SessionBinding::for('abc'))->not->toBe($before);
});

it('permits only one row per session binding', function (): void {
    $binding = SessionBinding::for('abc');

    AuthSession::create(['session_binding' => $binding, 'user_id' => 1, 'amr' => ['password']]);
    AuthSession::create(['session_binding' => $binding, 'user_id' => 2, 'amr' => ['password']]);
})->throws(\Illuminate\Database\QueryException::class);

it('rotates by updating the binding in place rather than adding a row', function (): void {
    $session = AuthSession::create([
        'session_binding' => SessionBinding::for('old-id'),
        'user_id' => 1,
        'amr' => ['recovery_code'],
        'recovery_grace_expires_at' => now()->addMinutes(15),
    ]);

    $session->update([
        'session_binding' => SessionBinding::for('new-id'),
        'amr' => ['totp'],
        'recovery_grace_expires_at' => null,
    ]);

    $fresh = AuthSession::findOrFail($session->getKey());

    expect(AuthSession::count())->toBe(1)
        ->and($fresh->amr)->toBe(['totp'])
        ->and($fresh->recovery_grace_expires_at)->toBeNull();
});

it('constrains the revocation reason to the known set', function (): void {
    $session = AuthSession::create([
        'session_binding' => SessionBinding::for('abc'),
        'user_id' => 1,
        'amr' => ['password'],
    ]);

    $session->update([
        'revoked_at' => now(),
        'revoked_reason' => RevokedReason::PasswordChanged,
    ]);

    expect(AuthSession::findOrFail($session->getKey())->revoked_reason)
        ->toBe(RevokedReason::PasswordChanged);
});

it('lists every revocation reason exactly once', function (): void {
    expect(array_map(fn (RevokedReason $r): string => $r->value, RevokedReason::cases()))
        ->toBe([
            'logout',
            'grace_expired',
            'credential_changed',
            'password_changed',
            'admin_revoked',
            'superseded',
        ]);
});
```

The `APP_KEY` test pins a documented consequence rather than an accident: rotating the key invalidates every session, which is already true of Laravel's encrypted cookies. If someone later switches the HMAC to an unkeyed hash for convenience, this test fails and asks why.

- [ ] **Step 2: Run to verify it fails**

Run: `vendor/bin/pest tests/Database/SessionsTest.php`
Expected: FAIL — `Class "Fissible\Vouch\Sessions\SessionBinding" not found`.

- [ ] **Step 3: Write the revocation reason enum**

Create `src/Sessions/RevokedReason.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

/**
 * Why a session was revoked.
 *
 * A closed set rather than free text: this value reaches user-facing sign-out
 * messaging, so free text would be an injection and disclosure surface on a
 * security-relevant path. A closed set also keeps revocations aggregatable in
 * audit, which is the point of recording them.
 */
enum RevokedReason: string
{
    case Logout = 'logout';
    case GraceExpired = 'grace_expired';
    case CredentialChanged = 'credential_changed';
    case PasswordChanged = 'password_changed';
    case AdminRevoked = 'admin_revoked';
    case Superseded = 'superseded';
}
```

- [ ] **Step 4: Write the session binding helper**

Create `src/Sessions/SessionBinding.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use RuntimeException;

/**
 * Derives the stored binding key for a host session.
 *
 * The host session ID is a bearer credential: anyone holding it is the session.
 * Storing it raw would turn any read of auth_sessions — SQL injection, a
 * backup, a read replica, a support export — into a pile of usable session
 * credentials. This is the same reasoning that hashes OTPs and recovery codes,
 * applied to the one other bearer value the schema touches.
 *
 * Keyed to APP_KEY, so rotating the key invalidates every session. That is
 * acceptable and already true of Laravel's encrypted session cookies.
 */
final class SessionBinding
{
    public static function for(string $hostSessionId): string
    {
        $key = config('app.key');

        if (! is_string($key) || $key === '') {
            throw new RuntimeException(
                'Vouch requires APP_KEY to be set: it keys the session binding HMAC.',
            );
        }

        return hash_hmac('sha256', $hostSessionId, $key);
    }
}
```

- [ ] **Step 5: Write the sessions migration**

Create `database/migrations/2026_08_12_000008_create_auth_sessions_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_sessions', function (Blueprint $table): void {
            $table->id();

            /*
             * HMAC-SHA256 of the host session ID, keyed to APP_KEY — never the
             * raw ID. Plain UNIQUE, not "unique among live rows": NULL != NULL
             * in a unique index on all three engines, so UNIQUE(binding,
             * revoked_at) would permit multiple live rows per binding, which is
             * the inverse of the intent. Rotation updates the row in place.
             */
            $table->string('session_binding', 64)->unique();

            $table->unsignedBigInteger('user_id')->index();
            $table->json('amr');
            $table->string('acr', 64)->nullable();
            $table->json('assurance_facts')->nullable();

            // Oldest satisfied factor, for §5.3 recency checks.
            $table->timestamp('last_factor_at')->nullable();

            // Absolute, set at creation, never extended (design §2, Expiry).
            $table->timestamp('recovery_grace_expires_at')->nullable();

            $table->timestamp('revoked_at')->nullable()->index();
            $table->string('revoked_reason', 32)->nullable();

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_sessions');
    }
};
```

- [ ] **Step 6: Write the model**

Create `src/Models/AuthSession.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Sessions\RevokedReason;
use Illuminate\Database\Eloquent\Model;

final class AuthSession extends Model
{
    protected $table = 'auth_sessions';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'amr' => 'array',
            'assurance_facts' => 'array',
            'last_factor_at' => 'datetime',
            'recovery_grace_expires_at' => 'datetime',
            'revoked_at' => 'datetime',
            'revoked_reason' => RevokedReason::class,
        ];
    }

    /**
     * Whether this is a recovery-grace session.
     *
     * The presence of recovery_grace_expires_at is the operative marker; the
     * amr containing only the recovery factor is the evidence that produced it.
     * Both are set together at creation and cleared together on completion.
     * This reads the marker rather than inspecting the amr, so that an amr
     * which is empty or malformed cannot be mistaken for a normal session —
     * the failure direction matters, and this one fails closed.
     */
    public function isRecoveryGrace(): bool
    {
        return $this->recovery_grace_expires_at !== null;
    }
}
```

- [ ] **Step 7: Run to verify it passes**

Run: `composer test && composer stan`
Expected: PASS (8 new tests), no PHPStan errors.

- [ ] **Step 8: Commit**

```bash
git add database/migrations/2026_08_12_000008_* src/Models/AuthSession.php \
        src/Sessions tests/Database/SessionsTest.php
git commit -m "feat: add session table with HMAC binding and constrained revocation"
```

---

## Task 7: Attempts and challenges

**Files:**
- Create: `database/migrations/2026_08_12_000009_create_auth_attempts_table.php`, `database/migrations/2026_08_12_000010_create_auth_challenges_table.php`
- Create: `src/Models/AuthAttempt.php`, `src/Models/AuthChallenge.php`
- Test: `tests/Database/AttemptsAndChallengesTest.php`

**Interfaces:**
- Consumes: `Fissible\Vouch\Kernel\Attempt\AttemptState` (Phase 1)
- Produces: `AuthAttempt` (`handle`, `state`, `version`, `tenant_id`, `identifier`, `bound_context`, `satisfied_factors`, `expires_at`); `AuthChallenge` (`attempt_id`, `factor_type`, `code_hash`, `attempts`, `bound_ip`, `bound_user_agent`, `expires_at`, `consumed_at`)

- [ ] **Step 1: Write the failing test**

Create `tests/Database/AttemptsAndChallengesTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function attempt(array $overrides = []): AuthAttempt
{
    return AuthAttempt::create(array_merge([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::Initiated,
        'version' => 1,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ], $overrides));
}

it('casts state to the kernel enum', function (): void {
    expect(AuthAttempt::findOrFail(attempt()->getKey())->state)->toBe(AttemptState::Initiated);
});

it('starts at version 1 and requires a unique handle', function (): void {
    $first = attempt();

    expect($first->version)->toBe(1);

    attempt(['handle' => $first->handle]);
})->throws(\Illuminate\Database\QueryException::class);

it('stores satisfied factors as an array', function (): void {
    $a = attempt(['satisfied_factors' => [['factor_id' => 'password', 'credential_id' => '7']]]);

    expect(AuthAttempt::findOrFail($a->getKey())->satisfied_factors)
        ->toBe([['factor_id' => 'password', 'credential_id' => '7']]);
});

it('never stores a challenge code in plaintext', function (): void {
    $challenge = AuthChallenge::create([
        'attempt_id' => attempt()->getKey(),
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', '123456'),
        'expires_at' => now()->addMinutes(2),
    ]);

    $fresh = AuthChallenge::findOrFail($challenge->getKey());

    expect($fresh->code_hash)->toBe(hash('sha256', '123456'))
        ->and($fresh->getAttributes())->not->toHaveKey('code');
});

it('deletes challenges when their attempt is deleted', function (): void {
    $a = attempt();
    AuthChallenge::create([
        'attempt_id' => $a->getKey(),
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', '123456'),
        'expires_at' => now()->addMinutes(2),
    ]);

    $a->delete();

    expect(AuthChallenge::count())->toBe(0);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `vendor/bin/pest tests/Database/AttemptsAndChallengesTest.php`
Expected: FAIL — `Class "Fissible\Vouch\Models\AuthAttempt" not found`.

- [ ] **Step 3: Write the attempts migration**

Create `database/migrations/2026_08_12_000009_create_auth_attempts_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_attempts', function (Blueprint $table): void {
            $table->id();

            // The opaque handle the client holds. Attempt state itself is never
            // client-trusted (parent spec §3.4).
            $table->string('handle', 64)->unique();

            $table->string('state', 32);

            // Monotonic, incremented on every transition. The CAS predicate.
            $table->unsignedBigInteger('version')->default(1);

            $table->string('tenant_id', 255)->nullable()->index();
            $table->string('identifier', 255)->nullable();
            $table->unsignedBigInteger('user_id')->nullable()->index();

            // Session/browser context the attempt was created under. A
            // transition presented from a different context is refused.
            $table->string('bound_context', 255)->nullable();

            $table->json('satisfied_factors')->nullable();
            $table->timestamp('expires_at')->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_attempts');
    }
};
```

- [ ] **Step 4: Write the challenges migration**

Create `database/migrations/2026_08_12_000010_create_auth_challenges_table.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_challenges', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('attempt_id')
                ->constrained('auth_attempts')
                ->cascadeOnDelete();

            $table->string('factor_type', 32);

            // Hashed, never plaintext (parent spec §7.6).
            $table->string('code_hash', 128);

            $table->unsignedInteger('attempts')->default(0);
            $table->string('bound_ip', 45)->nullable();
            $table->string('bound_user_agent', 512)->nullable();
            $table->timestamp('expires_at')->index();
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_challenges');
    }
};
```

- [ ] **Step 5: Write the models**

Create `src/Models/AuthAttempt.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

final class AuthAttempt extends Model
{
    protected $table = 'auth_attempts';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'state' => AttemptState::class,
            'version' => 'integer',
            'satisfied_factors' => 'array',
            'expires_at' => 'datetime',
        ];
    }

    /**
     * @return HasMany<AuthChallenge, $this>
     */
    public function challenges(): HasMany
    {
        return $this->hasMany(AuthChallenge::class, 'attempt_id');
    }
}
```

Create `src/Models/AuthChallenge.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Models;

use Illuminate\Database\Eloquent\Model;

final class AuthChallenge extends Model
{
    protected $table = 'auth_challenges';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'attempts' => 'integer',
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }
}
```

- [ ] **Step 6: Run to verify it passes**

Run: `composer test && composer stan`
Expected: PASS (5 new tests), no PHPStan errors.

- [ ] **Step 7: Commit**

```bash
git add database/migrations/2026_08_12_0000{09,10}_* src/Models/AuthAttempt.php \
        src/Models/AuthChallenge.php tests/Database/AttemptsAndChallengesTest.php
git commit -m "feat: add attempt and challenge tables and models"
```

---

## Task 8: The database attempt store

This is the security-critical component of 2.1. The concurrency *proof* is Task 9; this task builds the thing to be proven.

**Files:**
- Create: `src/Contracts/AttemptStore.php`, `src/Attempts/TransitionOutcome.php`, `src/Attempts/DatabaseAttemptStore.php`
- Modify: `src/VouchServiceProvider.php`
- Test: `tests/Database/AttemptStoreTest.php`

**Interfaces:**
- Consumes: `AuthAttempt`, `AuthChallenge` (Task 7); `AttemptState`, `TransitionRules` (Phase 1)
- Produces:
  - `TransitionOutcome` — backed enum: `Succeeded`, `IllegalTransition`, `Expired`, `ContextMismatch`, `ChallengeAlreadyConsumed`, `ConcurrentModification`
  - `AttemptStore::transition(AuthAttempt $attempt, AttemptState $to, ?int $consumeChallengeId = null): TransitionOutcome`

- [ ] **Step 1: Write the failing test**

Create `tests/Database/AttemptStoreTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function storeAttempt(array $overrides = []): AuthAttempt
{
    return AuthAttempt::create(array_merge([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::Initiated,
        'version' => 1,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ], $overrides));
}

function liveChallenge(AuthAttempt $attempt): AuthChallenge
{
    return AuthChallenge::create([
        'attempt_id' => $attempt->getKey(),
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', '123456'),
        'expires_at' => now()->addMinutes(2),
    ]);
}

it('advances a legal transition and increments the version', function (): void {
    $attempt = storeAttempt();

    $outcome = app(AttemptStore::class)->transition($attempt, AttemptState::Identified);

    $fresh = AuthAttempt::findOrFail($attempt->getKey());

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and($fresh->state)->toBe(AttemptState::Identified)
        ->and($fresh->version)->toBe(2);
});

it('refuses an illegal transition without writing', function (): void {
    $attempt = storeAttempt();

    $outcome = app(AttemptStore::class)->transition($attempt, AttemptState::Authenticated);

    $fresh = AuthAttempt::findOrFail($attempt->getKey());

    expect($outcome)->toBe(TransitionOutcome::IllegalTransition)
        ->and($fresh->state)->toBe(AttemptState::Initiated)
        ->and($fresh->version)->toBe(1);
});

it('refuses a transition on an expired attempt', function (): void {
    $attempt = storeAttempt(['expires_at' => now()->subSecond()]);

    expect(app(AttemptStore::class)->transition($attempt, AttemptState::Identified))
        ->toBe(TransitionOutcome::Expired);
});

it('refuses a transition presented from a different bound context', function (): void {
    $attempt = storeAttempt();
    $attempt->bound_context = 'sess-2';

    expect(app(AttemptStore::class)->transition($attempt, AttemptState::Identified))
        ->toBe(TransitionOutcome::ContextMismatch);
});

it('consumes a challenge and advances in one operation', function (): void {
    $attempt = storeAttempt(['state' => AttemptState::FactorPending, 'version' => 3]);
    $challenge = liveChallenge($attempt);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        $challenge->getKey(),
    );

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and(AuthChallenge::findOrFail($challenge->getKey())->consumed_at)->not->toBeNull()
        ->and(AuthAttempt::findOrFail($attempt->getKey())->version)->toBe(4);
});

it('refuses to advance on an already-consumed challenge and rolls back', function (): void {
    $attempt = storeAttempt(['state' => AttemptState::FactorPending, 'version' => 3]);
    $challenge = liveChallenge($attempt);
    $challenge->update(['consumed_at' => now()]);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        $challenge->getKey(),
    );

    $fresh = AuthAttempt::findOrFail($attempt->getKey());

    expect($outcome)->toBe(TransitionOutcome::ChallengeAlreadyConsumed)
        ->and($fresh->state)->toBe(AttemptState::FactorPending)
        ->and($fresh->version)->toBe(3);
});

it('refuses to advance on an expired challenge and rolls back', function (): void {
    $attempt = storeAttempt(['state' => AttemptState::FactorPending, 'version' => 3]);
    $challenge = liveChallenge($attempt);
    $challenge->update(['expires_at' => now()->subSecond()]);

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        $challenge->getKey(),
    );

    expect($outcome)->toBe(TransitionOutcome::ChallengeAlreadyConsumed)
        ->and(AuthAttempt::findOrFail($attempt->getKey())->version)->toBe(3);
});

it('refuses a transition whose version is stale', function (): void {
    $attempt = storeAttempt();

    // Someone else advanced it since this instance was read.
    AuthAttempt::whereKey($attempt->getKey())->update(['version' => 2]);

    expect(app(AttemptStore::class)->transition($attempt, AttemptState::Identified))
        ->toBe(TransitionOutcome::ConcurrentModification);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `vendor/bin/pest tests/Database/AttemptStoreTest.php`
Expected: FAIL — `Target class [Fissible\Vouch\Contracts\AttemptStore] does not exist.`

- [ ] **Step 3: Write the outcome enum**

Create `src/Attempts/TransitionOutcome.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

/**
 * The result of attempting an attempt-state transition.
 *
 * Every non-success value is a refusal, and every refusal leaves the stored
 * attempt exactly as it was.
 */
enum TransitionOutcome: string
{
    case Succeeded = 'succeeded';

    /** The kernel's TransitionRules rejected the move. Nothing was written. */
    case IllegalTransition = 'illegal_transition';

    /** The attempt has passed its hard expiry. */
    case Expired = 'expired';

    /** Presented from a session context other than the one it was bound to. */
    case ContextMismatch = 'context_mismatch';

    /** The challenge was already consumed or has expired. */
    case ChallengeAlreadyConsumed = 'challenge_already_consumed';

    /** Lost the compare-and-swap: another writer advanced the attempt first. */
    case ConcurrentModification = 'concurrent_modification';
}
```

- [ ] **Step 4: Write the contract**

Create `src/Contracts/AttemptStore.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;

/**
 * Persists in-progress authentication attempts.
 *
 * Responsibility split: the Phase 1 kernel's TransitionRules decides whether a
 * transition is *legal*; the store decides whether the caller *won the race*.
 * An implementation must never re-implement legality.
 */
interface AttemptStore
{
    /**
     * Attempt a state transition, optionally consuming a challenge atomically
     * with it.
     *
     * When $consumeChallengeId is given, the challenge consumption and the
     * attempt advance are all-or-nothing: if the challenge was already consumed
     * or has expired, the attempt does not advance.
     */
    public function transition(
        AuthAttempt $attempt,
        AttemptState $to,
        ?int $consumeChallengeId = null,
    ): TransitionOutcome;
}
```

- [ ] **Step 5: Write the database store**

Create `src/Attempts/DatabaseAttemptStore.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;
use Fissible\Vouch\Models\AuthAttempt;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Expression;

final class DatabaseAttemptStore implements AttemptStore
{
    public function __construct(
        private readonly ConnectionInterface $connection,
        private readonly TransitionRules $rules,
    ) {}

    public function transition(
        AuthAttempt $attempt,
        AttemptState $to,
        ?int $consumeChallengeId = null,
    ): TransitionOutcome {
        // Legality is the kernel's decision, and costs no write.
        if (! $this->rules->allows($attempt->state, $to)) {
            return TransitionOutcome::IllegalTransition;
        }

        // Pre-flight expiry and context checks. Expiry is ALSO in the guarded
        // UPDATE below — see the note on time-of-check/time-of-use.
        $stored = AuthAttempt::query()->find($attempt->getKey());

        if ($stored === null) {
            return TransitionOutcome::ConcurrentModification;
        }

        if ($stored->bound_context !== $attempt->bound_context) {
            return TransitionOutcome::ContextMismatch;
        }

        $outcome = TransitionOutcome::Succeeded;

        $this->connection->transaction(function () use (
            $attempt, $to, $consumeChallengeId, &$outcome
        ): void {
            if ($consumeChallengeId !== null) {
                $consumed = $this->connection->table('auth_challenges')
                    ->where('id', $consumeChallengeId)
                    ->where('attempt_id', $attempt->getKey())
                    ->whereNull('consumed_at')
                    ->where('expires_at', '>', $this->now())
                    ->update(['consumed_at' => $this->now()]);

                if ($consumed !== 1) {
                    $outcome = TransitionOutcome::ChallengeAlreadyConsumed;
                    $this->connection->rollBack();

                    return;
                }
            }

            $advanced = $this->connection->table('auth_attempts')
                ->where('id', $attempt->getKey())
                ->where('version', $attempt->version)
                ->where('expires_at', '>', $this->now())
                ->update([
                    'state' => $to->value,
                    'version' => new Expression('version + 1'),
                    'updated_at' => $this->now(),
                ]);

            if ($advanced !== 1) {
                $outcome = $this->expiredOrLostRace($attempt);
                $this->connection->rollBack();
            }
        });

        return $outcome;
    }

    /**
     * The database's current time, evaluated at statement execution.
     *
     * Deliberately NOT an application timestamp bound as a parameter. A
     * pre-flight check alone leaves a time-of-check/time-of-use window: the row
     * passes at T0, expires at T0.5, and the update still lands at T1. Binding
     * T0 would not close it — the predicate would compare against T0 and pass.
     * Evaluating at statement execution does. It follows that expires_at values
     * are written with the same clock, so no app-to-database skew can widen or
     * narrow a lifetime.
     */
    private function now(): Expression
    {
        return new Expression('CURRENT_TIMESTAMP');
    }

    /**
     * Distinguish "expired" from "lost the CAS" for a refused advance. Both
     * refuse; the caller deserves to know which.
     */
    private function expiredOrLostRace(AuthAttempt $attempt): TransitionOutcome
    {
        $stillLive = $this->connection->table('auth_attempts')
            ->where('id', $attempt->getKey())
            ->where('expires_at', '>', $this->now())
            ->exists();

        return $stillLive
            ? TransitionOutcome::ConcurrentModification
            : TransitionOutcome::Expired;
    }
}
```

- [ ] **Step 6: Bind the store**

In `src/VouchServiceProvider.php`, add to `register()`:

```php
        $this->app->singleton(
            \Fissible\Vouch\Contracts\AttemptStore::class,
            fn ($app) => new \Fissible\Vouch\Attempts\DatabaseAttemptStore(
                $app['db']->connection(),
                new \Fissible\Vouch\Kernel\Attempt\TransitionRules(),
            ),
        );
```

- [ ] **Step 7: Run to verify it passes**

Run: `composer test && composer stan`
Expected: PASS (8 new tests), no PHPStan errors.

If `rollBack()` inside a `transaction()` closure misbehaves on any driver, replace the closure form with explicit `beginTransaction()` / `commit()` / `rollBack()` calls. Do not swallow the outcome or return `Succeeded` on a rolled-back path.

- [ ] **Step 8: Commit**

```bash
git add src/Contracts/AttemptStore.php src/Attempts src/VouchServiceProvider.php \
        tests/Database/AttemptStoreTest.php
git commit -m "feat: add database attempt store with CAS transitions"
```

---

## Task 9: The adversarial concurrency matrix

The security deliverable of 2.1. Task 8's tests are sequential and prove the *logic*; these prove the *concurrency*, on every supported engine.

**Files:**
- Create: `tests/Concurrency/AttemptStoreContentionTest.php`
- Test: itself

**Interfaces:**
- Consumes: `AttemptStore`, `TransitionOutcome` (Task 8); `AuthAttempt`, `AuthChallenge` (Task 7)
- Produces: nothing consumed by later tasks

- [ ] **Step 1: Understand what makes this test real, before writing it**

Two connections to the same database, used in an interleaved order the store cannot detect. This genuinely races at the database level without needing parallel processes.

**It cannot run against `:memory:` SQLite.** Each connection to an in-memory SQLite database gets its own private database, so two "competing" connections would operate on unrelated data and every assertion would pass while proving nothing. The matrix therefore uses a file-backed SQLite path (`VOUCH_SQLITE_PATH`, set in CI), MySQL, and Postgres.

- [ ] **Step 2: Write the contention test**

Create `tests/Concurrency/AttemptStoreContentionTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\DatabaseAttemptStore;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

/*
 * DatabaseMigrations, NOT RefreshDatabase.
 *
 * RefreshDatabase wraps each test in a transaction on the default connection.
 * A second connection cannot see uncommitted rows from that transaction, so
 * every "racing" writer would operate on an empty table and every assertion
 * here would pass without anything having raced. That is the same vacuous
 * control this project has found five times, wearing a different costume.
 * DatabaseMigrations migrates fresh per test and commits, so both connections
 * see the same data.
 */
uses(DatabaseMigrations::class);

beforeEach(function (): void {
    // Register the two contending connections up front so every test — not
    // only those going through storeOn() — can use them.
    foreach (['race_a', 'race_b'] as $name) {
        config([
            'database.connections.' . $name => config(
                'database.connections.' . config('database.default'),
            ),
        ]);
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Contention tests need a shared database. In-memory SQLite gives each '
            . 'connection its own, so these would pass without racing. Set '
            . 'VOUCH_SQLITE_PATH to a file, as the CI matrix does.',
        );
    }
});

/** A store bound to its own connection, so two of them genuinely contend. */
function storeOn(string $name): DatabaseAttemptStore
{
    return new DatabaseAttemptStore(DB::connection($name), new TransitionRules());
}

function contendedAttempt(array $overrides = []): AuthAttempt
{
    return AuthAttempt::create(array_merge([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ], $overrides));
}

it('lets exactly one of two racing transitions win', function (): void {
    $attempt = contendedAttempt(['state' => AttemptState::Initiated]);

    // Both readers hold version 1.
    $a = AuthAttempt::findOrFail($attempt->getKey());
    $b = AuthAttempt::findOrFail($attempt->getKey());

    $first = storeOn('race_a')->transition($a, AttemptState::Identified);
    $second = storeOn('race_b')->transition($b, AttemptState::Identified);

    expect($first)->toBe(TransitionOutcome::Succeeded)
        ->and($second)->toBe(TransitionOutcome::ConcurrentModification)
        ->and(AuthAttempt::findOrFail($attempt->getKey())->version)->toBe(2);
});

it('consumes a challenge exactly once under contention', function (): void {
    $attempt = contendedAttempt();
    $challenge = AuthChallenge::create([
        'attempt_id' => $attempt->getKey(),
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', '123456'),
        'expires_at' => now()->addMinutes(2),
    ]);

    $a = AuthAttempt::findOrFail($attempt->getKey());
    $b = AuthAttempt::findOrFail($attempt->getKey());

    $outcomes = [
        storeOn('race_a')->transition($a, AttemptState::FactorSatisfied, $challenge->getKey()),
        storeOn('race_b')->transition($b, AttemptState::FactorSatisfied, $challenge->getKey()),
    ];

    $succeeded = array_filter($outcomes, fn (TransitionOutcome $o): bool => $o === TransitionOutcome::Succeeded);

    expect($succeeded)->toHaveCount(1)
        ->and(AuthAttempt::findOrFail($attempt->getKey())->version)->toBe(2);
});

it('leaves the challenge unconsumed when the losing writer rolls back', function (): void {
    $attempt = contendedAttempt();
    $challengeA = AuthChallenge::create([
        'attempt_id' => $attempt->getKey(),
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', 'aaa'),
        'expires_at' => now()->addMinutes(2),
    ]);
    $challengeB = AuthChallenge::create([
        'attempt_id' => $attempt->getKey(),
        'factor_type' => 'email_otp',
        'code_hash' => hash('sha256', 'bbb'),
        'expires_at' => now()->addMinutes(2),
    ]);

    $a = AuthAttempt::findOrFail($attempt->getKey());
    $b = AuthAttempt::findOrFail($attempt->getKey());

    storeOn('race_a')->transition($a, AttemptState::FactorSatisfied, $challengeA->getKey());
    $loser = storeOn('race_b')->transition($b, AttemptState::FactorSatisfied, $challengeB->getKey());

    // The loser's challenge must NOT stay consumed: its transaction rolled back.
    expect($loser)->toBe(TransitionOutcome::ConcurrentModification)
        ->and(AuthChallenge::findOrFail($challengeB->getKey())->consumed_at)->toBeNull()
        ->and(AuthChallenge::findOrFail($challengeA->getKey())->consumed_at)->not->toBeNull();
});

it('rejects a duplicate federated identity under concurrent insert', function (): void {
    $connection = \Fissible\Vouch\Models\AuthConnection::create([
        'tenant_id' => 'acme',
        'email_domain' => 'acme.example',
    ]);

    $row = [
        'connection_id' => $connection->getKey(),
        'issuer' => 'https://idp.acme.example',
        'subject' => 'sub-1',
        'created_at' => now(),
        'updated_at' => now(),
    ];

    DB::connection('race_a')->table('auth_federated_identities')->insert($row);

    expect(fn () => DB::connection('race_b')->table('auth_federated_identities')->insert($row))
        ->toThrow(\Illuminate\Database\QueryException::class);
});
```

The third test is the one most worth having: it proves the losing writer's challenge consumption is *rolled back*, not merely that its transition failed. Without the rollback, a lost race would burn a valid one-time code — a denial of service against a legitimate user, and invisible in a test that only asserts on the transition outcome.

- [ ] **Step 3: Run against SQLite in-memory and confirm it SKIPS**

Run: `vendor/bin/pest tests/Concurrency`
Expected: all tests skipped, with the message explaining why. A skip here is correct — it is the guard against a vacuous pass.

- [ ] **Step 4: Run against file-backed SQLite and confirm it PASSES**

Run:
```bash
VOUCH_SQLITE_PATH=/tmp/vouch-contention.sqlite vendor/bin/pest tests/Concurrency
```
Expected: PASS, not skipped. Delete the file afterwards.

- [ ] **Step 5: Prove the tests fail against a non-CAS store**

This is the step that makes the suite trustworthy. Temporarily edit `src/Attempts/DatabaseAttemptStore.php` to drop the CAS predicate — remove `->where('version', $attempt->version)` from the attempt update.

Run:
```bash
VOUCH_SQLITE_PATH=/tmp/vouch-contention.sqlite vendor/bin/pest tests/Concurrency
```
Expected: **FAIL** — the racing-transition and single-consumption tests must break.

Restore the predicate, re-run, confirm PASS. Record both outputs in your report. A concurrency suite that has never been observed failing is indistinguishable from one that cannot fail.

- [ ] **Step 6: Run the full suite and static analysis**

Run: `composer test && composer stan`
Expected: PASS with the concurrency tests skipped under the default in-memory config; no PHPStan errors.

- [ ] **Step 7: Commit**

```bash
git add tests/Concurrency/AttemptStoreContentionTest.php
git commit -m "test: add adversarial attempt-store contention matrix"
```

---

## Task 10: The housekeeping sweep

**Files:**
- Create: `src/Console/VouchPruneCommand.php`
- Modify: `src/VouchServiceProvider.php`
- Test: `tests/Database/PruneCommandTest.php`

**Interfaces:**
- Consumes: `AuthAttempt`, `AuthChallenge` (Task 7), `AuthSession` (Task 6), `config('vouch.sessions.revocation_retention_days')` (Task 1)
- Produces: the `vouch:prune` Artisan command

- [ ] **Step 1: Write the failing test**

Create `tests/Database/PruneCommandTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('deletes expired attempts and keeps live ones', function (): void {
    AuthAttempt::create([
        'handle' => 'expired', 'state' => AttemptState::Initiated, 'version' => 1,
        'expires_at' => now()->subMinute(),
    ]);
    AuthAttempt::create([
        'handle' => 'live', 'state' => AttemptState::Initiated, 'version' => 1,
        'expires_at' => now()->addMinute(),
    ]);

    $this->artisan('vouch:prune')->assertSuccessful();

    expect(AuthAttempt::pluck('handle')->all())->toBe(['live']);
});

it('deletes revoked sessions past the retention window and keeps recent ones', function (): void {
    config(['vouch.sessions.revocation_retention_days' => 30]);

    AuthSession::create([
        'session_binding' => SessionBinding::for('old'), 'user_id' => 1, 'amr' => ['password'],
        'revoked_at' => now()->subDays(31), 'revoked_reason' => RevokedReason::Logout,
    ]);
    AuthSession::create([
        'session_binding' => SessionBinding::for('recent'), 'user_id' => 1, 'amr' => ['password'],
        'revoked_at' => now()->subDays(29), 'revoked_reason' => RevokedReason::Logout,
    ]);

    $this->artisan('vouch:prune')->assertSuccessful();

    expect(AuthSession::count())->toBe(1)
        ->and(AuthSession::first()->session_binding)->toBe(SessionBinding::for('recent'));
});

it('never deletes a live session', function (): void {
    AuthSession::create([
        'session_binding' => SessionBinding::for('live'), 'user_id' => 1, 'amr' => ['password'],
    ]);

    $this->artisan('vouch:prune')->assertSuccessful();

    expect(AuthSession::count())->toBe(1);
});

it('does not delete an unrevoked session whose grace has expired', function (): void {
    AuthSession::create([
        'session_binding' => SessionBinding::for('grace'), 'user_id' => 1,
        'amr' => ['recovery_code'],
        'recovery_grace_expires_at' => now()->subHour(),
    ]);

    $this->artisan('vouch:prune')->assertSuccessful();

    expect(AuthSession::count())->toBe(1);
});
```

That last test encodes a rule that is easy to get backwards. **Grace expiry is enforced per-request, not by the sweep.** If the sweep deleted expired-grace rows, a request arriving between expiry and the sweep would find no row and could be treated as an ordinary unauthenticated visitor rather than a rejected grace session — and the sweep would have quietly become the enforcement mechanism it must never be.

- [ ] **Step 2: Run to verify it fails**

Run: `vendor/bin/pest tests/Database/PruneCommandTest.php`
Expected: FAIL — `The command "vouch:prune" does not exist.`

- [ ] **Step 3: Write the command**

Create `src/Console/VouchPruneCommand.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthSession;
use Illuminate\Console\Command;

/**
 * Housekeeping only.
 *
 * This command reaps dead rows. It is never the enforcement mechanism for any
 * expiry: attempt expiry is enforced in the store's guarded UPDATE predicates,
 * and recovery-grace expiry is enforced per-request on every vouch-owned route.
 * Deleting expired-grace rows here would turn a rejected grace session into an
 * anonymous one for any request arriving before the sweep.
 */
final class VouchPruneCommand extends Command
{
    protected $signature = 'vouch:prune';

    protected $description = 'Delete expired attempts and long-revoked sessions.';

    public function handle(): int
    {
        $attempts = AuthAttempt::query()
            ->where('expires_at', '<=', now())
            ->delete();

        $retentionDays = (int) config('vouch.sessions.revocation_retention_days', 30);

        $sessions = AuthSession::query()
            ->whereNotNull('revoked_at')
            ->where('revoked_at', '<=', now()->subDays($retentionDays))
            ->delete();

        $this->info(sprintf('Pruned %d attempt(s) and %d revoked session(s).', $attempts, $sessions));

        return self::SUCCESS;
    }
}
```

Challenges are removed by the `cascadeOnDelete()` on `auth_challenges.attempt_id`, so they need no separate sweep.

- [ ] **Step 4: Register the command**

In `src/VouchServiceProvider.php`, inside the `runningInConsole()` block in `boot()`:

```php
            $this->commands([
                \Fissible\Vouch\Console\VouchPruneCommand::class,
            ]);
```

- [ ] **Step 5: Run to verify it passes**

Run: `composer test && composer stan`
Expected: PASS (4 new tests), no PHPStan errors.

- [ ] **Step 6: Update `PROJECT.md`**

Add a Phase 2.1 row set to the roadmap table and refresh the session handoff notes with what 2.1 delivered and what 2.2 starts from. Do not touch `docs/superpowers/plans/` or the design specs.

- [ ] **Step 7: Commit**

```bash
git add src/Console src/VouchServiceProvider.php tests/Database/PruneCommandTest.php PROJECT.md
git commit -m "feat: add vouch:prune housekeeping command"
```

---

## Phase 2.1 Exit Criteria

- [ ] `composer test` green — kernel, arch, and database suites
- [ ] `composer stan` clean at level 9 over `src` and `tests`
- [ ] `composer mutate` still at or above its floors (kernel-scoped; unchanged by this phase)
- [ ] `composer validate --strict` passes
- [ ] The kernel boundary test demonstrated failing against a real `Illuminate` import (Task 1 Step 2)
- [ ] The `database-matrix` CI job green on SQLite, MySQL, and Postgres
- [ ] The contention suite demonstrated failing against a non-CAS store (Task 9 Step 5)
- [ ] The contention suite demonstrated skipping — not silently passing — against in-memory SQLite (Task 9 Step 3)
- [ ] Ten tables, ten models, three contracts in place
- [ ] `PROJECT.md` handoff updated

Phase 2.2 planning starts only after all of these hold.
