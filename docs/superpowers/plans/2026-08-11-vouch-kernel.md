# Vouch Kernel Implementation Plan (Phase 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `Fissible\Vouch\Kernel` — the pure-PHP decision logic for authentication policy, satisfiability, assurance, attempt transitions, and enumeration shaping — as a framework-free, mutation-tested library.

**Architecture:** Every class under `src/Kernel/` is immutable data or a pure function over that data. No persistence, no HTTP, no framework, no global time. Time enters only through an injected `Psr\Clock\ClockInterface`. A CI architecture test makes this a build failure rather than a convention. Phase 2 (the Laravel package) consumes this namespace; Phase 1 adds no Laravel dependency at all.

**Tech Stack:** PHP 8.4, `psr/clock`, Pest 3 (+ `pest-plugin-arch`), PHPStan level 9, Infection.

## Global Constraints

- **PHP `^8.4`.** No lower floor. (spec §6.1)
- **`Fissible\Vouch\Kernel` may depend on `php` and `psr/clock` and nothing else.** (spec §8.1)
- **Banned inside `src/Kernel/`:** `Illuminate\*`, any Laravel facade, global helpers (`app()`, `config()`, `now()`, `event()`), Eloquent types, driver namespaces, and global time (`time()`, `microtime()`, `date()`, `mktime()`, `strtotime()`, `new DateTime`, `new DateTimeImmutable`). (spec §8.1)
- **All kernel classes are `final readonly`** unless they hold no state at all, in which case `final`. Mutability disqualifies a class from the kernel. (spec §8.1)
- **Namespace root is `Fissible\Vouch\`**, matching `Fissible\Attest\` in the sibling package. The spec writes `Vouch\Kernel` as shorthand; the real namespace is `Fissible\Vouch\Kernel`.
- **`recovery`-strength satisfactions never contribute to a policy.** (spec §3.2, §7.3)
- **Conventional Commits.** `feat:`, `fix:`, `test:`, `chore:`, `docs:`. (org `CONTRIBUTING.md`)
- Work happens on the `design/auth-spec` branch or a branch cut from it. `main` is an empty root commit by design.

---

## File Structure

| File | Responsibility |
|---|---|
| `composer.json` | Package metadata, the two runtime deps, dev tooling, scripts |
| `phpstan.neon` | Level 9 across `src` and `tests` |
| `infection.json5` | Mutation testing scoped to `src/Kernel` |
| `.github/workflows/ci.yml` | OS × PHP matrix, mutation job, `validate` aggregate gate |
| `VERSION` | `0.1.0` |
| `src/Kernel/Factor/FactorKind.php` | `knowledge` / `possession` / `inherence` |
| `src/Kernel/Factor/FactorStrength.php` | Ordered strength enum with `atLeast()` |
| `src/Kernel/Factor/SatisfiedFactor.php` | Immutable record of one satisfied factor |
| `src/Kernel/Policy/Requirement.php` | Marker interface for the requirement tree |
| `src/Kernel/Policy/FactorRequirement.php` | Leaf: one factor with optional constraints |
| `src/Kernel/Policy/AllOf.php` | Conjunction + distinctness/independence constraints |
| `src/Kernel/Policy/AnyOf.php` | Disjunction |
| `src/Kernel/Policy/PolicyParser.php` | Config array → requirement tree, with validation |
| `src/Kernel/Policy/PolicyDocument.php` | A named requirement plus its enumeration posture |
| `src/Kernel/Policy/PolicyResolver.php` | global → tenant → role → user, most specific wins |
| `src/Kernel/Satisfiability/Verdict.php` | Satisfied/not, plus which factors were consumed |
| `src/Kernel/Satisfiability/SatisfiabilityEvaluator.php` | The matching algorithm |
| `src/Kernel/Assurance/AssuranceFacts.php` | Derived facts about a satisfaction set |
| `src/Kernel/Assurance/AssuranceVocabulary.php` | Facts → `acr` string (interface + default) |
| `src/Kernel/Assurance/AssuranceLevel.php` | An `acr` plus recency evaluation |
| `src/Kernel/Attempt/AttemptState.php` | The eight states from spec §3.4 |
| `src/Kernel/Attempt/TransitionRules.php` | Which transitions are legal |
| `src/Kernel/Screen/AuthStep.php` | `identify` / `challenge` / `enroll` / `recover` / `step_up` |
| `src/Kernel/Screen/FactorOption.php` | One offered factor |
| `src/Kernel/Screen/FieldSpec.php` | One input field |
| `src/Kernel/Screen/RetryPolicy.php` | Disclosable lockout/backoff state |
| `src/Kernel/Screen/ScreenSpec.php` | The whole screen, immutable |
| `src/Kernel/Enumeration/EnumerationPosture.php` | `strict` / `friendly` |
| `src/Kernel/Enumeration/Outcome.php` | What actually happened, pre-filtering |
| `src/Kernel/Enumeration/ErrorShaper.php` | Outcome + posture → disclosable errors |
| `tests/Arch/KernelBoundaryTest.php` | Enforces every ban in Global Constraints |
| `tests/Kernel/**` | Mirrors `src/Kernel/**` |

---

## Task 1: Package scaffolding and the kernel boundary test

The arch test is the deliverable here, not the scaffolding. It is written first because every later task must not be able to violate it.

**Files:**
- Create: `composer.json`, `phpstan.neon`, `infection.json5`, `VERSION`, `.github/workflows/ci.yml`
- Create: `tests/Pest.php`, `tests/Arch/KernelBoundaryTest.php`
- Create: `src/Kernel/.gitkeep`

**Interfaces:**
- Consumes: nothing
- Produces: `composer test`, `composer stan`, `composer mutate`; namespace roots `Fissible\Vouch\` → `src/`, `Fissible\Vouch\Tests\` → `tests/`

- [ ] **Step 1: Write `composer.json`**

```json
{
    "name": "fissible/vouch",
    "description": "Unified Laravel authentication: password, OTP, MFA, and SSO behind one policy engine.",
    "type": "library",
    "license": "MIT",
    "require": {
        "php": "^8.4",
        "psr/clock": "^1.0"
    },
    "require-dev": {
        "infection/infection": "^0.29",
        "pestphp/pest": "^3.0",
        "pestphp/pest-plugin-arch": "^3.0",
        "phpstan/phpstan": "^2.0"
    },
    "autoload": {
        "psr-4": {
            "Fissible\\Vouch\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "Fissible\\Vouch\\Tests\\": "tests/"
        }
    },
    "config": {
        "sort-packages": true,
        "allow-plugins": {
            "infection/extension-installer": true,
            "pestphp/pest-plugin": true
        }
    },
    "scripts": {
        "test": "pest",
        "stan": "phpstan analyse --no-progress",
        "mutate": "infection --threads=max --only-covered"
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
```

There is deliberately no `illuminate/*` dependency. Phase 1 is pure; the Laravel dependencies arrive in Phase 2. This makes the arch test cheap to satisfy and expensive to accidentally break.

- [ ] **Step 2: Write `phpstan.neon`**

```neon
parameters:
    level: 9
    paths:
        - src
        - tests
```

- [ ] **Step 3: Write `infection.json5`**

```json5
{
    "$schema": "vendor/infection/infection/resources/schema.json",
    "source": {
        "directories": ["src/Kernel"]
    },
    "mutators": {
        "@default": true
    },
    "minMsi": 85,
    "minCoveredMsi": 95,
    "logs": {
        "text": "build/infection.log"
    }
}
```

`minMsi` starts at 85 and is raised as coverage lands. Scoping `source.directories` to `src/Kernel` is what keeps this pass fast enough to stay in CI.

- [ ] **Step 4: Write `VERSION`**

```
0.1.0
```

- [ ] **Step 5: Write `tests/Pest.php`**

```php
<?php

declare(strict_types=1);
```

Pest requires the file to exist even when empty of configuration.

- [ ] **Step 6: Write the arch test**

Create `tests/Arch/KernelBoundaryTest.php`:

```php
<?php

declare(strict_types=1);

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

arch('kernel does not depend on any framework')
    ->expect('Fissible\Vouch\Kernel')
    ->not->toUse([
        'Illuminate',
        'Laravel',
        'Filament',
        'Livewire',
        'Symfony',
    ]);

arch('kernel does not call global helpers or global time')
    ->expect('Fissible\Vouch\Kernel')
    ->not->toUse([
        'app',
        'config',
        'now',
        'event',
        'dd',
        'dump',
        'time',
        'date',
        'microtime',
        'mktime',
        'strtotime',
    ]);

arch('kernel classes are final')
    ->expect('Fissible\Vouch\Kernel')
    ->classes()
    ->toBeFinal();

it('never instantiates a clock directly', function (): void {
    $offenders = [];

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(__DIR__ . '/../../src/Kernel'),
    );

    foreach ($files as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $source = (string) file_get_contents($file->getPathname());

        if (preg_match('/\bnew\s+\\\\?DateTime(Immutable)?\s*\(/', $source) === 1) {
            $offenders[] = $file->getPathname();
        }
    }

    expect($offenders)->toBeEmpty();
});
```

The final test exists because Pest's `toUse()` cannot distinguish *using* `DateTimeImmutable` as a parameter type — which the kernel must do — from *instantiating* one, which it must never do. A source scan is the honest way to catch that.

- [ ] **Step 7: Write the CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
        php: ['8.4']

    steps:
      - uses: actions/checkout@v5

      - name: Set up PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: ${{ matrix.php }}
          extensions: json, mbstring
          coverage: none

      - name: Validate composer.json
        run: composer validate --strict

      - name: Cache composer deps
        uses: actions/cache@v5
        with:
          path: vendor
          key: composer-${{ matrix.os }}-${{ matrix.php }}-${{ hashFiles('composer.json') }}

      - name: Install
        run: composer install --prefer-dist --no-progress

      - name: PHPStan
        run: composer stan

      - name: Pest
        run: composer test

  mutation:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v5

      - name: Set up PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          extensions: json, mbstring
          coverage: pcov

      - name: Install
        run: composer install --prefer-dist --no-progress

      - name: Infection
        run: composer mutate

  # Single stable required status check for branch protection. Requiring the
  # matrix jobs directly means their names embed the matrix values, so editing
  # the matrix silently drops required checks without failing anything.
  validate:
    name: validate
    runs-on: ubuntu-latest
    needs: [test, mutation]
    if: always()
    steps:
      - name: Require every upstream job to have succeeded
        if: contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled') || contains(needs.*.result, 'skipped')
        run: |
          echo "One or more CI jobs did not succeed: ${{ join(needs.*.result, ', ') }}"
          exit 1

      - run: echo "All CI jobs succeeded."
```

The mutation job needs `coverage: pcov`; the test matrix does not and is faster without it.

- [ ] **Step 8: Install and run the suite**

Run:
```bash
composer install
mkdir -p src/Kernel && touch src/Kernel/.gitkeep
composer test
```
Expected: PASS. The arch expectations pass vacuously against an empty namespace, and the clock-instantiation test finds no files. This confirms the harness runs before any behaviour depends on it.

- [ ] **Step 9: Commit**

```bash
git add composer.json composer.lock phpstan.neon infection.json5 VERSION \
        .github/workflows/ci.yml tests/Pest.php tests/Arch/KernelBoundaryTest.php \
        src/Kernel/.gitkeep
git commit -m "chore: scaffold package and enforce the kernel boundary in CI"
```

---

## Task 2: Factor kind and strength enums

**Files:**
- Create: `src/Kernel/Factor/FactorKind.php`, `src/Kernel/Factor/FactorStrength.php`
- Test: `tests/Kernel/Factor/FactorStrengthTest.php`

**Interfaces:**
- Consumes: nothing
- Produces: `FactorKind::{Knowledge,Possession,Inherence}`; `FactorStrength::{Recovery,Knowledge,PossessionWeak,Possession,PossessionStrong}` with `atLeast(self): bool`

- [ ] **Step 1: Write the failing test**

Create `tests/Kernel/Factor/FactorStrengthTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorStrength;

it('orders strengths from weakest to strongest', function (): void {
    expect(FactorStrength::PossessionStrong->atLeast(FactorStrength::Possession))->toBeTrue()
        ->and(FactorStrength::Possession->atLeast(FactorStrength::PossessionWeak))->toBeTrue()
        ->and(FactorStrength::PossessionWeak->atLeast(FactorStrength::Knowledge))->toBeTrue();
});

it('treats a strength as satisfying itself', function (): void {
    expect(FactorStrength::Possession->atLeast(FactorStrength::Possession))->toBeTrue();
});

it('rejects a weaker strength', function (): void {
    expect(FactorStrength::PossessionWeak->atLeast(FactorStrength::PossessionStrong))->toBeFalse();
});

it('ranks recovery below every real factor', function (): void {
    expect(FactorStrength::Recovery->atLeast(FactorStrength::Knowledge))->toBeFalse();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `vendor/bin/pest tests/Kernel/Factor/FactorStrengthTest.php`
Expected: FAIL with `Class "Fissible\Vouch\Kernel\Factor\FactorStrength" not found`

- [ ] **Step 3: Write the enums**

Create `src/Kernel/Factor/FactorKind.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Factor;

enum FactorKind: string
{
    case Knowledge = 'knowledge';
    case Possession = 'possession';
    case Inherence = 'inherence';
}
```

Create `src/Kernel/Factor/FactorStrength.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Factor;

/**
 * Ordered by real-world security, not convenience: passkey > totp > sms > email.
 *
 * Recovery sorts lowest, but ordering is NOT the mechanism that excludes it from
 * satisfying a policy — SatisfiabilityEvaluator filters it explicitly. Relying on
 * ordering alone would let a policy with no minimum strength accept a recovery code
 * as a normal factor.
 */
enum FactorStrength: int
{
    case Recovery = 0;
    case Knowledge = 10;
    case PossessionWeak = 20;
    case Possession = 30;
    case PossessionStrong = 40;

    public function atLeast(self $minimum): bool
    {
        return $this->value >= $minimum->value;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `vendor/bin/pest tests/Kernel/Factor/FactorStrengthTest.php`
Expected: PASS (4 tests)

- [ ] **Step 5: Run the arch test**

Run: `composer test`
Expected: PASS. Confirms the new files satisfy the boundary.

- [ ] **Step 6: Commit**

```bash
git add src/Kernel/Factor tests/Kernel/Factor
git commit -m "feat: add factor kind and ordered strength enums"
```

---

## Task 3: The `SatisfiedFactor` value object

This is the §3.6 record — the structured evidence that satisfiability is evaluated over.

**Files:**
- Create: `src/Kernel/Factor/SatisfiedFactor.php`
- Test: `tests/Kernel/Factor/SatisfiedFactorTest.php`

**Interfaces:**
- Consumes: `FactorKind`, `FactorStrength` (Task 2)
- Produces: `SatisfiedFactor` with public readonly properties `factorId`, `credentialId`, `kind`, `strength`, `isMultiFactor`, `userVerified`, `phishingResistant`, `authenticatorId`, `satisfiedAt`

- [ ] **Step 1: Write the failing test**

Create `tests/Kernel/Factor/SatisfiedFactorTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

it('records everything satisfiability needs', function (): void {
    $at = new DateTimeImmutable('2026-08-11T10:00:00+00:00');

    $factor = new SatisfiedFactor(
        factorId: 'passkey',
        credentialId: 'cred-1',
        kind: FactorKind::Possession,
        strength: FactorStrength::PossessionStrong,
        isMultiFactor: true,
        userVerified: true,
        phishingResistant: true,
        authenticatorId: 'auth-1',
        satisfiedAt: $at,
    );

    expect($factor->factorId)->toBe('passkey')
        ->and($factor->credentialId)->toBe('cred-1')
        ->and($factor->kind)->toBe(FactorKind::Possession)
        ->and($factor->strength)->toBe(FactorStrength::PossessionStrong)
        ->and($factor->isMultiFactor)->toBeTrue()
        ->and($factor->userVerified)->toBeTrue()
        ->and($factor->phishingResistant)->toBeTrue()
        ->and($factor->authenticatorId)->toBe('auth-1')
        ->and($factor->satisfiedAt)->toBe($at);
});

it('allows a null authenticator for factors with no device', function (): void {
    $factor = new SatisfiedFactor(
        factorId: 'password',
        credentialId: 'cred-2',
        kind: FactorKind::Knowledge,
        strength: FactorStrength::Knowledge,
        isMultiFactor: false,
        userVerified: false,
        phishingResistant: false,
        authenticatorId: null,
        satisfiedAt: new DateTimeImmutable('2026-08-11T10:00:00+00:00'),
    );

    expect($factor->authenticatorId)->toBeNull();
});
```

`new DateTimeImmutable(...)` in a *test* is fine — the ban applies to `src/Kernel`, and the arch test only scans there.

- [ ] **Step 2: Run test to verify it fails**

Run: `vendor/bin/pest tests/Kernel/Factor/SatisfiedFactorTest.php`
Expected: FAIL with `Class "Fissible\Vouch\Kernel\Factor\SatisfiedFactor" not found`

- [ ] **Step 3: Write the value object**

Create `src/Kernel/Factor/SatisfiedFactor.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Factor;

use DateTimeImmutable;

/**
 * One factor, actually satisfied, with everything policy needs to judge it.
 *
 * `isMultiFactor` is true for a user-verified passkey: possession of the
 * authenticator plus a biometric or PIN, which NIST treats as AAL2 on its own.
 * `authenticatorId` distinguishes two credentials living on the same device,
 * which are not independent authenticators.
 */
final readonly class SatisfiedFactor
{
    public function __construct(
        public string $factorId,
        public string $credentialId,
        public FactorKind $kind,
        public FactorStrength $strength,
        public bool $isMultiFactor,
        public bool $userVerified,
        public bool $phishingResistant,
        public ?string $authenticatorId,
        public DateTimeImmutable $satisfiedAt,
    ) {}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `composer test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/Kernel/Factor/SatisfiedFactor.php tests/Kernel/Factor/SatisfiedFactorTest.php
git commit -m "feat: add SatisfiedFactor value object"
```

---

## Task 4: The requirement tree and policy parsing

**Files:**
- Create: `src/Kernel/Policy/Requirement.php`, `FactorRequirement.php`, `AllOf.php`, `AnyOf.php`, `PolicyParser.php`
- Test: `tests/Kernel/Policy/PolicyParserTest.php`

**Interfaces:**
- Consumes: `FactorStrength` (Task 2)
- Produces:
  - `interface Requirement {}` (marker)
  - `FactorRequirement(string $factorId, ?bool $userVerified = null, ?FactorStrength $minimumStrength = null, ?bool $phishingResistant = null)`
  - `AllOf(array $requirements, bool $requireDistinctCredentials = true, bool $requireIndependentAuthenticators = false)`
  - `AnyOf(array $requirements)`
  - `PolicyParser::parse(array $config): Requirement`, throwing `InvalidArgumentException` on malformed input

- [ ] **Step 1: Write the failing test**

Create `tests/Kernel/Policy/PolicyParserTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\AnyOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;
use Fissible\Vouch\Kernel\Policy\PolicyParser;

it('parses a bare factor name into a leaf requirement', function (): void {
    $parsed = (new PolicyParser())->parse(['all_of' => ['password']]);

    // assert() rather than expect()->toBeInstanceOf(): PHPStan runs over tests at
    // level 9 and needs the narrowing before the property accesses below.
    assert($parsed instanceof AllOf);
    $leaf = $parsed->requirements[0];
    assert($leaf instanceof FactorRequirement);

    expect($parsed->requirements)->toHaveCount(1)
        ->and($leaf->factorId)->toBe('password');
});

it('parses leaf constraints', function (): void {
    $parsed = (new PolicyParser())->parse([
        'all_of' => [
            ['factor' => 'passkey', 'user_verified' => true, 'minimum_strength' => 'possession'],
        ],
    ]);

    assert($parsed instanceof AllOf);
    $leaf = $parsed->requirements[0];
    assert($leaf instanceof FactorRequirement);

    expect($leaf->factorId)->toBe('passkey')
        ->and($leaf->userVerified)->toBeTrue()
        ->and($leaf->minimumStrength)->toBe(FactorStrength::Possession);
});

it('defaults distinct credentials to required and independence to not required', function (): void {
    $parsed = (new PolicyParser())->parse(['all_of' => ['password', 'totp']]);

    assert($parsed instanceof AllOf);

    expect($parsed->requireDistinctCredentials)->toBeTrue()
        ->and($parsed->requireIndependentAuthenticators)->toBeFalse();
});

it('parses the mfa preset shape', function (): void {
    $parsed = (new PolicyParser())->parse([
        'any_of' => [
            ['all_of' => [['factor' => 'passkey', 'user_verified' => true]]],
            [
                'all_of' => ['password', 'totp'],
                'require_distinct_credentials' => true,
                'require_independent_authenticators' => true,
            ],
        ],
    ]);

    assert($parsed instanceof AnyOf);
    $second = $parsed->requirements[1];
    assert($second instanceof AllOf);

    expect($parsed->requirements)->toHaveCount(2)
        ->and($second->requireIndependentAuthenticators)->toBeTrue();
});

it('rejects a node that is neither all_of nor any_of', function (): void {
    expect(fn () => (new PolicyParser())->parse(['some_of' => ['password']]))
        ->toThrow(InvalidArgumentException::class, 'must declare exactly one of');
});

it('rejects an empty branch', function (): void {
    expect(fn () => (new PolicyParser())->parse(['all_of' => []]))
        ->toThrow(InvalidArgumentException::class, 'must not be empty');
});

it('rejects an unknown strength name', function (): void {
    expect(fn () => (new PolicyParser())->parse([
        'all_of' => [['factor' => 'password', 'minimum_strength' => 'extremely']],
    ]))->toThrow(InvalidArgumentException::class, 'unknown minimum_strength');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `vendor/bin/pest tests/Kernel/Policy/PolicyParserTest.php`
Expected: FAIL with `Class "Fissible\Vouch\Kernel\Policy\PolicyParser" not found`

- [ ] **Step 3: Write the requirement tree**

Create `src/Kernel/Policy/Requirement.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

/**
 * Marker. The tree is pure data; SatisfiabilityEvaluator holds the algorithm, so
 * that the one piece of logic worth mutation-testing lives in one place.
 */
interface Requirement {}
```

Create `src/Kernel/Policy/FactorRequirement.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

use Fissible\Vouch\Kernel\Factor\FactorStrength;

final readonly class FactorRequirement implements Requirement
{
    public function __construct(
        public string $factorId,
        public ?bool $userVerified = null,
        public ?FactorStrength $minimumStrength = null,
        public ?bool $phishingResistant = null,
    ) {}
}
```

Create `src/Kernel/Policy/AllOf.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

final readonly class AllOf implements Requirement
{
    /**
     * @param non-empty-list<Requirement> $requirements
     */
    public function __construct(
        public array $requirements,
        public bool $requireDistinctCredentials = true,
        public bool $requireIndependentAuthenticators = false,
    ) {}
}
```

Create `src/Kernel/Policy/AnyOf.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

final readonly class AnyOf implements Requirement
{
    /**
     * @param non-empty-list<Requirement> $requirements
     */
    public function __construct(public array $requirements) {}
}
```

- [ ] **Step 4: Write the parser**

Create `src/Kernel/Policy/PolicyParser.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

use Fissible\Vouch\Kernel\Factor\FactorStrength;
use InvalidArgumentException;

final class PolicyParser
{
    /**
     * @param array<string, mixed> $config
     */
    public function parse(array $config): Requirement
    {
        $hasAll = array_key_exists('all_of', $config);
        $hasAny = array_key_exists('any_of', $config);

        if ($hasAll === $hasAny) {
            throw new InvalidArgumentException(
                'A policy node must declare exactly one of all_of or any_of.',
            );
        }

        $key = $hasAll ? 'all_of' : 'any_of';
        $children = $config[$key];

        if (! is_array($children) || $children === []) {
            throw new InvalidArgumentException(
                sprintf('A policy node\'s %s must not be empty.', $key),
            );
        }

        $parsed = array_map($this->parseChild(...), array_values($children));

        if ($hasAny) {
            return new AnyOf($parsed);
        }

        return new AllOf(
            requirements: $parsed,
            requireDistinctCredentials: (bool) ($config['require_distinct_credentials'] ?? true),
            requireIndependentAuthenticators: (bool) ($config['require_independent_authenticators'] ?? false),
        );
    }

    private function parseChild(mixed $child): Requirement
    {
        if (is_string($child)) {
            return new FactorRequirement($child);
        }

        if (! is_array($child)) {
            throw new InvalidArgumentException(
                'A policy child must be a factor name or an array.',
            );
        }

        if (array_key_exists('all_of', $child) || array_key_exists('any_of', $child)) {
            return $this->parse($child);
        }

        if (! array_key_exists('factor', $child) || ! is_string($child['factor'])) {
            throw new InvalidArgumentException(
                'A leaf policy node must declare a string factor.',
            );
        }

        return new FactorRequirement(
            factorId: $child['factor'],
            userVerified: isset($child['user_verified']) ? (bool) $child['user_verified'] : null,
            minimumStrength: $this->parseStrength($child['minimum_strength'] ?? null),
            phishingResistant: isset($child['phishing_resistant']) ? (bool) $child['phishing_resistant'] : null,
        );
    }

    private function parseStrength(mixed $name): ?FactorStrength
    {
        if ($name === null) {
            return null;
        }

        $strength = match ($name) {
            'recovery' => FactorStrength::Recovery,
            'knowledge' => FactorStrength::Knowledge,
            'possession_weak' => FactorStrength::PossessionWeak,
            'possession' => FactorStrength::Possession,
            'possession_strong' => FactorStrength::PossessionStrong,
            default => null,
        };

        if ($strength === null) {
            throw new InvalidArgumentException(
                sprintf('unknown minimum_strength: %s', var_export($name, true)),
            );
        }

        return $strength;
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `composer test`
Expected: PASS (7 new tests)

- [ ] **Step 6: Run PHPStan**

Run: `composer stan`
Expected: no errors. If it complains that `$parsed` is not `non-empty-list`, add `/** @var non-empty-list<Requirement> $parsed */` above the `if ($hasAny)` line — the emptiness was already checked but PHPStan cannot see through `array_map`.

- [ ] **Step 7: Commit**

```bash
git add src/Kernel/Policy tests/Kernel/Policy
git commit -m "feat: add requirement tree and policy array parsing"
```

---

## Task 5: The satisfiability evaluator

The highest-risk component in the kernel. Built over five test cycles rather than one, because each cycle pins a distinct failure mode.

**Files:**
- Create: `src/Kernel/Satisfiability/Verdict.php`, `src/Kernel/Satisfiability/SatisfiabilityEvaluator.php`
- Test: `tests/Kernel/Satisfiability/SatisfiabilityEvaluatorTest.php`

**Interfaces:**
- Consumes: `SatisfiedFactor` (Task 3); `Requirement`, `FactorRequirement`, `AllOf`, `AnyOf` (Task 4)
- Produces: `SatisfiabilityEvaluator::evaluate(Requirement $requirement, array $satisfied): Verdict`; `Verdict` with `bool $satisfied` and `list<SatisfiedFactor> $usedFactors`

- [ ] **Step 1: Write the test helper and the first two failing tests**

Create `tests/Kernel/Satisfiability/SatisfiabilityEvaluatorTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\AnyOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;
use Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator;

function factor(
    string $factorId,
    string $credentialId,
    FactorStrength $strength = FactorStrength::Possession,
    bool $userVerified = false,
    bool $phishingResistant = false,
    ?string $authenticatorId = null,
): SatisfiedFactor {
    return new SatisfiedFactor(
        factorId: $factorId,
        credentialId: $credentialId,
        kind: FactorKind::Possession,
        strength: $strength,
        isMultiFactor: $userVerified,
        userVerified: $userVerified,
        phishingResistant: $phishingResistant,
        authenticatorId: $authenticatorId,
        satisfiedAt: new DateTimeImmutable('2026-08-11T10:00:00+00:00'),
    );
}

it('satisfies a single leaf requirement', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('password')]),
        [factor('password', 'cred-1')],
    );

    expect($verdict->satisfied)->toBeTrue()
        ->and($verdict->usedFactors)->toHaveCount(1);
});

it('fails when the required factor is absent', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('totp')]),
        [factor('password', 'cred-1')],
    );

    expect($verdict->satisfied)->toBeFalse()
        ->and($verdict->usedFactors)->toBeEmpty();
});
```

- [ ] **Step 2: Run to verify failure**

Run: `vendor/bin/pest tests/Kernel/Satisfiability`
Expected: FAIL with `Class "Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator" not found`

- [ ] **Step 3: Write `Verdict` and a minimal evaluator**

Create `src/Kernel/Satisfiability/Verdict.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Satisfiability;

use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

final readonly class Verdict
{
    /**
     * @param list<SatisfiedFactor> $usedFactors
     */
    private function __construct(
        public bool $satisfied,
        public array $usedFactors,
    ) {}

    public static function unsatisfied(): self
    {
        return new self(false, []);
    }

    /**
     * @param list<SatisfiedFactor> $factors
     */
    public static function satisfiedBy(array $factors): self
    {
        return new self(true, $factors);
    }
}
```

Create `src/Kernel/Satisfiability/SatisfiabilityEvaluator.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Satisfiability;

use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\AnyOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;
use Fissible\Vouch\Kernel\Policy\Requirement;

final class SatisfiabilityEvaluator
{
    /**
     * @param list<SatisfiedFactor> $satisfied
     */
    public function evaluate(Requirement $requirement, array $satisfied): Verdict
    {
        $solutions = $this->solve($requirement, $satisfied);

        return $solutions === []
            ? Verdict::unsatisfied()
            : Verdict::satisfiedBy($solutions[0]);
    }

    /**
     * Every distinct factor set that satisfies $requirement.
     *
     * @param list<SatisfiedFactor> $pool
     * @return list<list<SatisfiedFactor>>
     */
    private function solve(Requirement $requirement, array $pool): array
    {
        return match (true) {
            $requirement instanceof FactorRequirement => $this->solveLeaf($requirement, $pool),
            $requirement instanceof AnyOf => $this->solveAnyOf($requirement, $pool),
            $requirement instanceof AllOf => $this->solveAllOf($requirement, $pool),
            default => [],
        };
    }

    /**
     * @param list<SatisfiedFactor> $pool
     * @return list<list<SatisfiedFactor>>
     */
    private function solveLeaf(FactorRequirement $requirement, array $pool): array
    {
        $solutions = [];

        foreach ($pool as $candidate) {
            if ($this->leafMatches($requirement, $candidate)) {
                $solutions[] = [$candidate];
            }
        }

        return $solutions;
    }

    private function leafMatches(FactorRequirement $requirement, SatisfiedFactor $factor): bool
    {
        if ($factor->factorId !== $requirement->factorId) {
            return false;
        }

        if ($requirement->userVerified !== null && $factor->userVerified !== $requirement->userVerified) {
            return false;
        }

        if ($requirement->phishingResistant !== null && $factor->phishingResistant !== $requirement->phishingResistant) {
            return false;
        }

        if ($requirement->minimumStrength !== null && ! $factor->strength->atLeast($requirement->minimumStrength)) {
            return false;
        }

        return true;
    }

    /**
     * @param list<SatisfiedFactor> $pool
     * @return list<list<SatisfiedFactor>>
     */
    private function solveAnyOf(AnyOf $requirement, array $pool): array
    {
        $solutions = [];

        foreach ($requirement->requirements as $child) {
            foreach ($this->solve($child, $pool) as $solution) {
                $solutions[] = $solution;
            }
        }

        return $solutions;
    }

    /**
     * @param list<SatisfiedFactor> $pool
     * @return list<list<SatisfiedFactor>>
     */
    private function solveAllOf(AllOf $requirement, array $pool): array
    {
        /** @var list<list<SatisfiedFactor>> $accumulated */
        $accumulated = [[]];

        foreach ($requirement->requirements as $child) {
            $next = [];

            foreach ($accumulated as $partial) {
                foreach ($this->solve($child, $pool) as $addition) {
                    if ($this->compatible($requirement, $partial, $addition)) {
                        $next[] = [...$partial, ...$addition];
                    }
                }
            }

            if ($next === []) {
                return [];
            }

            $accumulated = $next;
        }

        return $accumulated;
    }

    /**
     * @param list<SatisfiedFactor> $partial
     * @param list<SatisfiedFactor> $addition
     */
    private function compatible(AllOf $requirement, array $partial, array $addition): bool
    {
        foreach ($addition as $incoming) {
            foreach ($partial as $existing) {
                if ($requirement->requireDistinctCredentials
                    && $existing->credentialId === $incoming->credentialId) {
                    return false;
                }

                if ($requirement->requireIndependentAuthenticators
                    && $existing->authenticatorId !== null
                    && $existing->authenticatorId === $incoming->authenticatorId) {
                    return false;
                }
            }
        }

        return true;
    }
}
```

The accumulate-partial-solutions shape is what makes distinctness work. A greedy "pick the first match per requirement" pass would fail whenever the first match for requirement A is the only possible match for requirement B.

- [ ] **Step 4: Run to verify the first two tests pass**

Run: `vendor/bin/pest tests/Kernel/Satisfiability`
Expected: PASS (2 tests)

- [ ] **Step 5: Add the distinctness tests**

Append to `tests/Kernel/Satisfiability/SatisfiabilityEvaluatorTest.php`:

```php
it('refuses to count one credential as two factors', function (): void {
    $passkey = factor('passkey', 'cred-1', userVerified: true);

    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('passkey'), new FactorRequirement('passkey')]),
        [$passkey],
    );

    expect($verdict->satisfied)->toBeFalse();
});

it('accepts two distinct credentials of the same factor', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('passkey'), new FactorRequirement('passkey')]),
        [factor('passkey', 'cred-1'), factor('passkey', 'cred-2')],
    );

    expect($verdict->satisfied)->toBeTrue()
        ->and($verdict->usedFactors)->toHaveCount(2);
});

it('allows one credential to serve twice when distinctness is waived', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf(
            [new FactorRequirement('passkey'), new FactorRequirement('passkey')],
            requireDistinctCredentials: false,
        ),
        [factor('passkey', 'cred-1')],
    );

    expect($verdict->satisfied)->toBeTrue();
});

it('backtracks rather than greedily consuming the only match for another requirement', function (): void {
    // 'shared' matches both requirements; 'totp-only' matches only the second.
    // A greedy first-match pass assigns 'shared' to requirement one and then
    // has nothing left for requirement two.
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([
            new FactorRequirement('totp', minimumStrength: FactorStrength::Possession),
            new FactorRequirement('totp', minimumStrength: FactorStrength::PossessionStrong),
        ]),
        [
            factor('totp', 'cred-strong', FactorStrength::PossessionStrong),
            factor('totp', 'cred-weak', FactorStrength::Possession),
        ],
    );

    expect($verdict->satisfied)->toBeTrue();
});
```

- [ ] **Step 6: Run to verify they pass**

Run: `vendor/bin/pest tests/Kernel/Satisfiability`
Expected: PASS (6 tests). All pass against the Step 3 implementation — these tests pin behaviour the algorithm already has, so that a later "simplification" to a greedy loop fails loudly.

- [ ] **Step 7: Add authenticator-independence tests**

Append:

```php
it('rejects two credentials on the same authenticator when independence is required', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf(
            [new FactorRequirement('passkey'), new FactorRequirement('passkey')],
            requireIndependentAuthenticators: true,
        ),
        [
            factor('passkey', 'cred-1', authenticatorId: 'device-1'),
            factor('passkey', 'cred-2', authenticatorId: 'device-1'),
        ],
    );

    expect($verdict->satisfied)->toBeFalse();
});

it('accepts credentials on different authenticators', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf(
            [new FactorRequirement('passkey'), new FactorRequirement('passkey')],
            requireIndependentAuthenticators: true,
        ),
        [
            factor('passkey', 'cred-1', authenticatorId: 'device-1'),
            factor('passkey', 'cred-2', authenticatorId: 'device-2'),
        ],
    );

    expect($verdict->satisfied)->toBeTrue();
});
```

- [ ] **Step 8: Run to verify they pass**

Run: `vendor/bin/pest tests/Kernel/Satisfiability`
Expected: PASS (8 tests)

- [ ] **Step 9: Add the failing recovery-exclusion test**

Append:

```php
it('never lets a recovery code satisfy a policy', function (): void {
    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        new AllOf([new FactorRequirement('recovery_code')]),
        [factor('recovery_code', 'cred-1', FactorStrength::Recovery)],
    );

    expect($verdict->satisfied)->toBeFalse();
});
```

- [ ] **Step 10: Run to verify it fails**

Run: `vendor/bin/pest tests/Kernel/Satisfiability`
Expected: FAIL — the evaluator currently matches the leaf and returns satisfied.

- [ ] **Step 11: Filter recovery in `evaluate()`**

In `src/Kernel/Satisfiability/SatisfiabilityEvaluator.php`, replace the body of `evaluate()`:

```php
    /**
     * @param list<SatisfiedFactor> $satisfied
     */
    public function evaluate(Requirement $requirement, array $satisfied): Verdict
    {
        // Recovery grants a restricted recovery-grace session (spec §7.3); it never
        // contributes to a policy. Filtered here rather than relying on strength
        // ordering, so a policy with no minimum strength still cannot accept it.
        $eligible = array_values(array_filter(
            $satisfied,
            static fn (SatisfiedFactor $factor): bool => $factor->strength !== FactorStrength::Recovery,
        ));

        $solutions = $this->solve($requirement, $eligible);

        return $solutions === []
            ? Verdict::unsatisfied()
            : Verdict::satisfiedBy($solutions[0]);
    }
```

- [ ] **Step 12: Run to verify all pass**

Run: `composer test && composer stan`
Expected: PASS (9 evaluator tests), no PHPStan errors

- [ ] **Step 13: Add the mfa-preset integration test**

Append:

```php
it('accepts a user-verified passkey alone under the mfa preset', function (): void {
    $mfa = new AnyOf([
        new AllOf([new FactorRequirement('passkey', userVerified: true)]),
        new AllOf(
            [new FactorRequirement('password'), new FactorRequirement('totp')],
            requireIndependentAuthenticators: true,
        ),
    ]);

    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        $mfa,
        [factor('passkey', 'cred-1', FactorStrength::PossessionStrong, userVerified: true)],
    );

    expect($verdict->satisfied)->toBeTrue()
        ->and($verdict->usedFactors)->toHaveCount(1);
});

it('rejects a passkey without user verification under the mfa preset', function (): void {
    $mfa = new AnyOf([
        new AllOf([new FactorRequirement('passkey', userVerified: true)]),
        new AllOf([new FactorRequirement('password'), new FactorRequirement('totp')]),
    ]);

    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        $mfa,
        [factor('passkey', 'cred-1', FactorStrength::PossessionStrong, userVerified: false)],
    );

    expect($verdict->satisfied)->toBeFalse();
});

it('accepts password plus totp under the mfa preset', function (): void {
    $mfa = new AnyOf([
        new AllOf([new FactorRequirement('passkey', userVerified: true)]),
        new AllOf([new FactorRequirement('password'), new FactorRequirement('totp')]),
    ]);

    $verdict = (new SatisfiabilityEvaluator())->evaluate(
        $mfa,
        [
            factor('password', 'cred-1', FactorStrength::Knowledge),
            factor('totp', 'cred-2', FactorStrength::Possession),
        ],
    );

    expect($verdict->satisfied)->toBeTrue()
        ->and($verdict->usedFactors)->toHaveCount(2);
});
```

- [ ] **Step 14: Run to verify they pass**

Run: `composer test`
Expected: PASS (12 evaluator tests)

- [ ] **Step 15: Run mutation testing on the evaluator**

Run: `composer mutate`
Expected: MSI ≥ 85. If escaped mutants are reported, read `build/infection.log` and add a test for each escapee before continuing. Escaped mutants here are the exact class of defect this component exists to prevent.

- [ ] **Step 16: Commit**

```bash
git add src/Kernel/Satisfiability tests/Kernel/Satisfiability
git commit -m "feat: add satisfiability evaluator with distinctness and independence"
```

---

## Task 6: The policy resolution chain

**Files:**
- Create: `src/Kernel/Policy/PolicyDocument.php`, `src/Kernel/Policy/PolicyResolver.php`
- Test: `tests/Kernel/Policy/PolicyResolverTest.php`

**Interfaces:**
- Consumes: `Requirement` (Task 4), `EnumerationPosture` (Task 10 — create the enum here, Task 10 adds its consumer)
- Produces: `PolicyDocument(Requirement $requirement, EnumerationPosture $posture)`; `PolicyResolver::resolve(array $layers): PolicyDocument` where `$layers` is ordered least-to-most specific and may contain nulls

The resolver is deliberately given an ordered array rather than a tenant object. Reading tenants from a database is Phase 2's job; the kernel only decides precedence.

- [ ] **Step 1: Write the failing test**

Create `tests/Kernel/Policy/PolicyResolverTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;
use Fissible\Vouch\Kernel\Policy\PolicyDocument;
use Fissible\Vouch\Kernel\Policy\PolicyResolver;

function document(string $factorId, EnumerationPosture $posture = EnumerationPosture::Friendly): PolicyDocument
{
    return new PolicyDocument(
        requirement: new AllOf([new FactorRequirement($factorId)]),
        posture: $posture,
    );
}

/** Narrows the resolved requirement for PHPStan and reads its single factor id. */
function resolvedFactorId(PolicyDocument $document): string
{
    $requirement = $document->requirement;
    assert($requirement instanceof AllOf);

    $leaf = $requirement->requirements[0];
    assert($leaf instanceof FactorRequirement);

    return $leaf->factorId;
}

it('returns the only layer when just one is present', function (): void {
    $resolved = (new PolicyResolver())->resolve([document('password')]);

    expect(resolvedFactorId($resolved))->toBe('password');
});

it('prefers the most specific layer', function (): void {
    $resolved = (new PolicyResolver())->resolve([
        document('password'),   // global
        document('totp'),       // tenant
        document('passkey'),    // role
    ]);

    expect(resolvedFactorId($resolved))->toBe('passkey');
});

it('skips null layers', function (): void {
    $resolved = (new PolicyResolver())->resolve([
        document('password'),
        null,
        null,
    ]);

    expect(resolvedFactorId($resolved))->toBe('password');
});

it('takes the strictest posture across all layers, not the most specific', function (): void {
    $resolved = (new PolicyResolver())->resolve([
        document('password', EnumerationPosture::Strict),
        document('totp', EnumerationPosture::Friendly),
    ]);

    expect($resolved->posture)->toBe(EnumerationPosture::Strict);
});

it('rejects an empty layer set', function (): void {
    expect(fn () => (new PolicyResolver())->resolve([]))
        ->toThrow(InvalidArgumentException::class, 'at least one policy layer');
});

it('rejects a layer set that is entirely null', function (): void {
    expect(fn () => (new PolicyResolver())->resolve([null, null]))
        ->toThrow(InvalidArgumentException::class, 'at least one policy layer');
});
```

The posture rule is deliberately *not* most-specific-wins. A tenant loosening enumeration posture below the global setting would be a downgrade an operator did not intend; strictest-wins makes the global value a floor.

- [ ] **Step 2: Run to verify failure**

Run: `vendor/bin/pest tests/Kernel/Policy/PolicyResolverTest.php`
Expected: FAIL with `Class "Fissible\Vouch\Kernel\Enumeration\EnumerationPosture" not found`

- [ ] **Step 3: Write the posture enum**

Create `src/Kernel/Enumeration/EnumerationPosture.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Enumeration;

enum EnumerationPosture: string
{
    case Friendly = 'friendly';
    case Strict = 'strict';

    public function isAtLeastAsStrictAs(self $other): bool
    {
        return $this === self::Strict || $other === self::Friendly;
    }
}
```

- [ ] **Step 4: Write `PolicyDocument`**

Create `src/Kernel/Policy/PolicyDocument.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;

final readonly class PolicyDocument
{
    public function __construct(
        public Requirement $requirement,
        public EnumerationPosture $posture,
    ) {}
}
```

- [ ] **Step 5: Write `PolicyResolver`**

Create `src/Kernel/Policy/PolicyResolver.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use InvalidArgumentException;

final class PolicyResolver
{
    /**
     * @param list<PolicyDocument|null> $layers ordered least specific first:
     *                                          global, tenant, role, user
     */
    public function resolve(array $layers): PolicyDocument
    {
        $present = array_values(array_filter(
            $layers,
            static fn (?PolicyDocument $layer): bool => $layer instanceof PolicyDocument,
        ));

        if ($present === []) {
            throw new InvalidArgumentException('Resolution requires at least one policy layer.');
        }

        $mostSpecific = $present[count($present) - 1];

        return new PolicyDocument(
            requirement: $mostSpecific->requirement,
            posture: $this->strictestPosture($present),
        );
    }

    /**
     * @param non-empty-list<PolicyDocument> $layers
     */
    private function strictestPosture(array $layers): EnumerationPosture
    {
        $strictest = EnumerationPosture::Friendly;

        foreach ($layers as $layer) {
            if ($layer->posture->isAtLeastAsStrictAs($strictest)) {
                $strictest = $layer->posture;
            }
        }

        return $strictest;
    }
}
```

- [ ] **Step 6: Run to verify tests pass**

Run: `composer test && composer stan`
Expected: PASS (6 new tests), no PHPStan errors

- [ ] **Step 7: Commit**

```bash
git add src/Kernel/Policy/PolicyDocument.php src/Kernel/Policy/PolicyResolver.php \
        src/Kernel/Enumeration/EnumerationPosture.php tests/Kernel/Policy/PolicyResolverTest.php
git commit -m "feat: add policy resolution chain with strictest-posture floor"
```

---

## Task 7: Assurance level derivation and recency

The spec leaves the assurance *vocabulary* open (NIST AAL names vs OIDC `acr` URIs vs a vouch-specific scale). This task does not wait on that decision: it derives structured facts and hands naming to an injectable `AssuranceVocabulary`, so the choice becomes configuration rather than a code change.

**Files:**
- Create: `src/Kernel/Assurance/AssuranceFacts.php`, `AssuranceVocabulary.php`, `NistAssuranceVocabulary.php`, `AssuranceLevel.php`
- Test: `tests/Kernel/Assurance/AssuranceLevelTest.php`

**Interfaces:**
- Consumes: `SatisfiedFactor`, `FactorStrength` (Tasks 2–3); `Psr\Clock\ClockInterface`
- Produces:
  - `AssuranceFacts::fromFactors(array $factors): self` with `int $distinctCredentialCount`, `FactorStrength $strongest`, `bool $allPhishingResistant`, `?DateTimeImmutable $weakestSatisfiedAt`
  - `interface AssuranceVocabulary { public function name(AssuranceFacts $facts): string; }`
  - `AssuranceLevel(string $acr, AssuranceFacts $facts)` with `satisfiesRecency(DateInterval $maxAge, ClockInterface $clock): bool`

- [ ] **Step 1: Write the failing test**

Create `tests/Kernel/Assurance/AssuranceLevelTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Assurance\AssuranceLevel;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Kernel\Assurance\NistAssuranceVocabulary;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Psr\Clock\ClockInterface;

function at(string $iso): DateTimeImmutable
{
    return new DateTimeImmutable($iso);
}

function frozenClock(string $iso): ClockInterface
{
    return new class(at($iso)) implements ClockInterface {
        public function __construct(private readonly DateTimeImmutable $now) {}

        public function now(): DateTimeImmutable
        {
            return $this->now;
        }
    };
}

function satisfied(
    string $credentialId,
    FactorStrength $strength,
    bool $phishingResistant,
    string $iso,
    bool $multiFactor = false,
): SatisfiedFactor {
    return new SatisfiedFactor(
        factorId: 'f',
        credentialId: $credentialId,
        kind: FactorKind::Possession,
        strength: $strength,
        isMultiFactor: $multiFactor,
        userVerified: $multiFactor,
        phishingResistant: $phishingResistant,
        authenticatorId: null,
        satisfiedAt: at($iso),
    );
}

it('counts distinct credentials, not satisfactions', function (): void {
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:01:00+00:00'),
        satisfied('cred-2', FactorStrength::Possession, false, '2026-08-11T10:02:00+00:00'),
    ]);

    expect($facts->distinctCredentialCount)->toBe(2);
});

it('reports the strongest factor', function (): void {
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-2', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00'),
    ]);

    expect($facts->strongest)->toBe(FactorStrength::PossessionStrong);
});

it('is phishing resistant only when every factor is', function (): void {
    $mixed = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-2', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00'),
    ]);

    expect($mixed->allPhishingResistant)->toBeFalse();
});

it('takes recency from the oldest factor, not the newest', function (): void {
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T08:00:00+00:00'),
        satisfied('cred-2', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00'),
    ]);

    expect($facts->weakestSatisfiedAt?->format('H:i'))->toBe('08:00');
});

it('fails recency when the oldest factor is beyond max age', function (): void {
    $level = new AssuranceLevel('aal2', AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Possession, false, '2026-08-11T08:00:00+00:00'),
    ]));

    $withinTwoHours = $level->satisfiesRecency(
        new DateInterval('PT2H'),
        frozenClock('2026-08-11T11:00:00+00:00'),
    );

    expect($withinTwoHours)->toBeFalse();
});

it('passes recency inside max age', function (): void {
    $level = new AssuranceLevel('aal2', AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00'),
    ]));

    $withinTwoHours = $level->satisfiesRecency(
        new DateInterval('PT2H'),
        frozenClock('2026-08-11T11:00:00+00:00'),
    );

    expect($withinTwoHours)->toBeTrue();
});

it('names two distinct credentials aal2 under the NIST vocabulary', function (): void {
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-2', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00'),
    ]);

    expect((new NistAssuranceVocabulary())->name($facts))->toBe('aal2');
});

it('caps at aal2 for a phishing-resistant strong passkey', function (): void {
    // AAL3 additionally requires a non-exportable key in hardware. A syncable
    // passkey is phishing-resistant but not AAL3-eligible, and the kernel records
    // no hardware-binding evidence either way — so the default must never emit it.
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00', multiFactor: true),
    ]);

    expect((new NistAssuranceVocabulary())->name($facts))->toBe('aal2');
});

it('never emits aal3 for any input the kernel can represent', function (): void {
    $vocabulary = new NistAssuranceVocabulary();

    $everyShape = [
        AssuranceFacts::fromFactors([]),
        AssuranceFacts::fromFactors([
            satisfied('cred-1', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
        ]),
        AssuranceFacts::fromFactors([
            satisfied('cred-1', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00', multiFactor: true),
        ]),
        AssuranceFacts::fromFactors([
            satisfied('cred-1', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00', multiFactor: true),
            satisfied('cred-2', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00', multiFactor: true),
        ]),
    ];

    foreach ($everyShape as $facts) {
        expect($vocabulary->name($facts))->not->toBe('aal3');
    }
});

it('lets an application supply a vocabulary that reads phishing resistance', function (): void {
    // Demonstrates the extension point, and is the reason AssuranceFacts exposes
    // allPhishingResistant even though the conservative default does not read it.
    $strict = new class implements AssuranceVocabulary {
        public function name(AssuranceFacts $facts): string
        {
            return $facts->allPhishingResistant ? 'acme:strong' : 'acme:standard';
        }
    };

    $resistant = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00'),
    ]);

    $mixed = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::PossessionStrong, true, '2026-08-11T10:00:00+00:00'),
        satisfied('cred-2', FactorStrength::Knowledge, false, '2026-08-11T10:00:00+00:00'),
    ]);

    expect($strict->name($resistant))->toBe('acme:strong')
        ->and($strict->name($mixed))->toBe('acme:standard');
});

it('names one multi-factor credential aal2 rather than aal1', function (): void {
    // A user-verified passkey is possession plus a biometric or PIN: one
    // credential, two factors. Counting credentials alone would call this aal1.
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00', multiFactor: true),
    ]);

    expect($facts->hasMultiFactorCredential)->toBeTrue()
        ->and((new NistAssuranceVocabulary())->name($facts))->toBe('aal2');
});

it('names one single-factor credential aal1', function (): void {
    $facts = AssuranceFacts::fromFactors([
        satisfied('cred-1', FactorStrength::Possession, false, '2026-08-11T10:00:00+00:00'),
    ]);

    expect((new NistAssuranceVocabulary())->name($facts))->toBe('aal1');
});
```

- [ ] **Step 2: Run to verify failure**

Run: `vendor/bin/pest tests/Kernel/Assurance`
Expected: FAIL with `Class "Fissible\Vouch\Kernel\Assurance\AssuranceFacts" not found`

- [ ] **Step 3: Write `AssuranceFacts`**

Create `src/Kernel/Assurance/AssuranceFacts.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Assurance;

use DateTimeImmutable;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

final readonly class AssuranceFacts
{
    public function __construct(
        public int $distinctCredentialCount,
        public FactorStrength $strongest,
        public bool $allPhishingResistant,
        public bool $hasMultiFactorCredential,
        public ?DateTimeImmutable $weakestSatisfiedAt,
    ) {}

    /**
     * @param list<SatisfiedFactor> $factors
     */
    public static function fromFactors(array $factors): self
    {
        if ($factors === []) {
            return new self(0, FactorStrength::Recovery, false, false, null);
        }

        $credentialIds = [];
        $strongest = FactorStrength::Recovery;
        $allPhishingResistant = true;
        $hasMultiFactorCredential = false;
        $oldest = null;

        foreach ($factors as $factor) {
            $credentialIds[$factor->credentialId] = true;

            if ($factor->strength->atLeast($strongest)) {
                $strongest = $factor->strength;
            }

            if (! $factor->phishingResistant) {
                $allPhishingResistant = false;
            }

            if ($factor->isMultiFactor) {
                $hasMultiFactorCredential = true;
            }

            // Recency is governed by the oldest factor: a session is only as
            // fresh as its stalest evidence.
            if ($oldest === null || $factor->satisfiedAt < $oldest) {
                $oldest = $factor->satisfiedAt;
            }
        }

        return new self(
            distinctCredentialCount: count($credentialIds),
            strongest: $strongest,
            allPhishingResistant: $allPhishingResistant,
            hasMultiFactorCredential: $hasMultiFactorCredential,
            weakestSatisfiedAt: $oldest,
        );
    }
}
```

- [ ] **Step 4: Write the vocabulary interface and default**

Create `src/Kernel/Assurance/AssuranceVocabulary.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Assurance;

/**
 * Names an assurance level from derived facts.
 *
 * Exists so the choice between NIST AAL names, OIDC acr URIs, and an
 * application-specific scale is configuration rather than a code change — the
 * name ends up in the public RFC 9470 acr_values string (spec §6.3), so it must
 * be swappable without touching derivation.
 */
interface AssuranceVocabulary
{
    public function name(AssuranceFacts $facts): string;
}
```

Create `src/Kernel/Assurance/NistAssuranceVocabulary.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Assurance;

/**
 * Conservative NIST-flavoured naming. Caps at aal2 by design.
 *
 * AAL3 additionally requires a hardware-based authenticator whose private key is
 * non-exportable — syncable passkeys are explicitly ineligible even though they
 * are phishing-resistant. AssuranceFacts carries no hardware-binding evidence, so
 * emitting aal3 here would assert something the kernel never observed. Phishing
 * resistance alone is an AAL2 property, not an AAL3 one.
 *
 * An application that does capture hardware binding (WebAuthn backup-eligibility
 * and backup-state flags, or attestation) can ship its own AssuranceVocabulary —
 * that extension point is why this class is not the interface.
 *
 * @see https://pages.nist.gov/800-63-4/sp800-63b/aal/
 */
final class NistAssuranceVocabulary implements AssuranceVocabulary
{
    public function name(AssuranceFacts $facts): string
    {
        if ($facts->distinctCredentialCount === 0) {
            return 'aal0';
        }

        // One user-verified passkey is possession plus a biometric or PIN — two
        // factors on one credential. Counting credentials alone would understate it.
        if ($facts->distinctCredentialCount >= 2 || $facts->hasMultiFactorCredential) {
            return 'aal2';
        }

        return 'aal1';
    }
}
```

- [ ] **Step 5: Write `AssuranceLevel`**

Create `src/Kernel/Assurance/AssuranceLevel.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Assurance;

use DateInterval;
use Psr\Clock\ClockInterface;

final readonly class AssuranceLevel
{
    public function __construct(
        public string $acr,
        public AssuranceFacts $facts,
    ) {}

    public function satisfiesRecency(DateInterval $maxAge, ClockInterface $clock): bool
    {
        $oldest = $this->facts->weakestSatisfiedAt;

        if ($oldest === null) {
            return false;
        }

        return $oldest >= $clock->now()->sub($maxAge);
    }
}
```

- [ ] **Step 6: Run to verify tests pass**

Run: `composer test && composer stan`
Expected: PASS (12 new tests), no PHPStan errors

- [ ] **Step 7: Verify the arch test still holds**

Run: `vendor/bin/pest tests/Arch`
Expected: PASS. `AssuranceLevel` takes `DateTimeImmutable` as a type and calls `$clock->now()`, but never instantiates a clock — this is the case the source-scan test exists for.

- [ ] **Step 8: Commit**

```bash
git add src/Kernel/Assurance tests/Kernel/Assurance
git commit -m "feat: derive assurance facts and levels with injectable vocabulary"
```

---

## Task 8: Attempt transition rules

**Files:**
- Create: `src/Kernel/Attempt/AttemptState.php`, `src/Kernel/Attempt/TransitionRules.php`
- Test: `tests/Kernel/Attempt/TransitionRulesTest.php`

**Interfaces:**
- Consumes: nothing
- Produces: `AttemptState` (eight cases); `TransitionRules::allows(AttemptState $from, AttemptState $to): bool`, `TransitionRules::isTerminal(AttemptState $state): bool`

Persistence, CAS, and expiry are Phase 2 (spec §4.3). This task owns only which transitions are legal.

- [ ] **Step 1: Write the failing test**

Create `tests/Kernel/Attempt/TransitionRulesTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;

it('walks the happy path', function (): void {
    $rules = new TransitionRules();

    expect($rules->allows(AttemptState::Initiated, AttemptState::Identified))->toBeTrue()
        ->and($rules->allows(AttemptState::Identified, AttemptState::FactorPending))->toBeTrue()
        ->and($rules->allows(AttemptState::FactorPending, AttemptState::FactorSatisfied))->toBeTrue()
        ->and($rules->allows(AttemptState::FactorSatisfied, AttemptState::Authenticated))->toBeTrue();
});

it('allows another factor round after one is satisfied', function (): void {
    expect((new TransitionRules())->allows(AttemptState::FactorSatisfied, AttemptState::FactorPending))
        ->toBeTrue();
});

it('routes an unknown identifier to registration', function (): void {
    expect((new TransitionRules())->allows(AttemptState::Identified, AttemptState::RegistrationRequired))
        ->toBeTrue();
});

it('never authenticates straight from initiated', function (): void {
    expect((new TransitionRules())->allows(AttemptState::Initiated, AttemptState::Authenticated))
        ->toBeFalse();
});

it('never authenticates without a satisfied factor', function (): void {
    expect((new TransitionRules())->allows(AttemptState::Identified, AttemptState::Authenticated))
        ->toBeFalse()
        ->and((new TransitionRules())->allows(AttemptState::FactorPending, AttemptState::Authenticated))
        ->toBeFalse();
});

it('treats terminal states as terminal', function (): void {
    $rules = new TransitionRules();

    foreach ([AttemptState::Authenticated, AttemptState::Failed, AttemptState::Locked, AttemptState::RegistrationRequired] as $terminal) {
        expect($rules->isTerminal($terminal))->toBeTrue();

        foreach (AttemptState::cases() as $target) {
            expect($rules->allows($terminal, $target))->toBeFalse();
        }
    }
});

it('can fail or lock from any live state', function (): void {
    $rules = new TransitionRules();

    foreach ([AttemptState::Initiated, AttemptState::Identified, AttemptState::FactorPending, AttemptState::FactorSatisfied] as $live) {
        expect($rules->allows($live, AttemptState::Failed))->toBeTrue()
            ->and($rules->allows($live, AttemptState::Locked))->toBeTrue();
    }
});

it('never allows a state to transition to itself', function (): void {
    $rules = new TransitionRules();

    foreach (AttemptState::cases() as $state) {
        expect($rules->allows($state, $state))->toBeFalse();
    }
});
```

- [ ] **Step 2: Run to verify failure**

Run: `vendor/bin/pest tests/Kernel/Attempt`
Expected: FAIL with `Class "Fissible\Vouch\Kernel\Attempt\AttemptState" not found`

- [ ] **Step 3: Write the state enum**

Create `src/Kernel/Attempt/AttemptState.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Attempt;

enum AttemptState: string
{
    case Initiated = 'initiated';
    case Identified = 'identified';
    case FactorPending = 'factor_pending';
    case FactorSatisfied = 'factor_satisfied';
    case Authenticated = 'authenticated';
    case RegistrationRequired = 'registration_required';
    case Failed = 'failed';
    case Locked = 'locked';
}
```

- [ ] **Step 4: Write the transition rules**

Create `src/Kernel/Attempt/TransitionRules.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Attempt;

final class TransitionRules
{
    private const TERMINAL = [
        AttemptState::Authenticated->value,
        AttemptState::RegistrationRequired->value,
        AttemptState::Failed->value,
        AttemptState::Locked->value,
    ];

    /**
     * Legal forward transitions. Failed and Locked are reachable from any live
     * state and are added at check time rather than repeated in every row.
     *
     * @var array<string, list<AttemptState>>
     */
    private const FORWARD = [
        AttemptState::Initiated->value => [
            AttemptState::Identified,
        ],
        AttemptState::Identified->value => [
            AttemptState::FactorPending,
            AttemptState::RegistrationRequired,
        ],
        AttemptState::FactorPending->value => [
            AttemptState::FactorSatisfied,
        ],
        AttemptState::FactorSatisfied->value => [
            AttemptState::FactorPending,
            AttemptState::Authenticated,
        ],
    ];

    public function allows(AttemptState $from, AttemptState $to): bool
    {
        if ($from === $to) {
            return false;
        }

        if ($this->isTerminal($from)) {
            return false;
        }

        if ($to === AttemptState::Failed || $to === AttemptState::Locked) {
            return true;
        }

        return in_array($to, self::FORWARD[$from->value] ?? [], strict: true);
    }

    public function isTerminal(AttemptState $state): bool
    {
        return in_array($state->value, self::TERMINAL, strict: true);
    }
}
```

- [ ] **Step 5: Run to verify tests pass**

Run: `composer test && composer stan`
Expected: PASS (8 new tests), no PHPStan errors

- [ ] **Step 6: Commit**

```bash
git add src/Kernel/Attempt tests/Kernel/Attempt
git commit -m "feat: add attempt state machine transition rules"
```

---

## Task 9: Screen specification value objects

**Files:**
- Create: `src/Kernel/Screen/AuthStep.php`, `FactorOption.php`, `FieldSpec.php`, `RetryPolicy.php`, `ScreenSpec.php`
- Test: `tests/Kernel/Screen/ScreenSpecTest.php`

**Interfaces:**
- Consumes: `FactorStrength` (Task 2)
- Produces: `ScreenSpec(AuthStep $step, array $offeredFactors, array $fields, ?array $challengePayload, array $errors, ?RetryPolicy $retry)`

`challengePayload` is a plain `array<string, mixed>` rather than a typed object: its contents are WebAuthn options, an OTP delivery hint, or an OIDC redirect, all of which are driver-shaped and therefore Phase 2's concern. Typing it here would drag driver knowledge into the kernel.

- [ ] **Step 1: Write the failing test**

Create `tests/Kernel/Screen/ScreenSpecTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\FactorOption;
use Fissible\Vouch\Kernel\Screen\FieldSpec;
use Fissible\Vouch\Kernel\Screen\RetryPolicy;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;

it('carries everything an adapter needs to render', function (): void {
    $spec = new ScreenSpec(
        step: AuthStep::Challenge,
        offeredFactors: [
            new FactorOption('passkey', 'Use a passkey', FactorStrength::PossessionStrong, isDefault: true),
            new FactorOption('totp', 'Use an authenticator app', FactorStrength::Possession, isDefault: false),
        ],
        fields: [new FieldSpec('code', 'text', 'one-time-code', maxLength: 6)],
        challengePayload: ['delivery' => 'email'],
        errors: [],
        retry: new RetryPolicy(attemptsRemaining: 4, lockedUntil: null),
    );

    expect($spec->step)->toBe(AuthStep::Challenge)
        ->and($spec->offeredFactors)->toHaveCount(2)
        ->and($spec->offeredFactors[0]->isDefault)->toBeTrue()
        ->and($spec->fields[0]->autocomplete)->toBe('one-time-code')
        ->and($spec->fields[0]->maxLength)->toBe(6)
        ->and($spec->challengePayload)->toBe(['delivery' => 'email'])
        ->and($spec->retry?->attemptsRemaining)->toBe(4);
});

it('supports a screen with no challenge and no retry disclosure', function (): void {
    $spec = new ScreenSpec(
        step: AuthStep::Identify,
        offeredFactors: [],
        fields: [new FieldSpec('identifier', 'email', 'username', maxLength: null)],
        challengePayload: null,
        errors: ['Check your email.'],
        retry: null,
    );

    expect($spec->challengePayload)->toBeNull()
        ->and($spec->retry)->toBeNull()
        ->and($spec->errors)->toBe(['Check your email.']);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `vendor/bin/pest tests/Kernel/Screen`
Expected: FAIL with `Class "Fissible\Vouch\Kernel\Screen\AuthStep" not found`

- [ ] **Step 3: Write the value objects**

Create `src/Kernel/Screen/AuthStep.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

enum AuthStep: string
{
    case Identify = 'identify';
    case Challenge = 'challenge';
    case Enroll = 'enroll';
    case Recover = 'recover';
    case StepUp = 'step_up';
}
```

Create `src/Kernel/Screen/FactorOption.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

use Fissible\Vouch\Kernel\Factor\FactorStrength;

final readonly class FactorOption
{
    public function __construct(
        public string $factorId,
        public string $label,
        public FactorStrength $strength,
        public bool $isDefault,
    ) {}
}
```

Create `src/Kernel/Screen/FieldSpec.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

final readonly class FieldSpec
{
    public function __construct(
        public string $name,
        public string $type,
        public string $autocomplete,
        public ?int $maxLength,
    ) {}
}
```

Create `src/Kernel/Screen/RetryPolicy.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

use DateTimeImmutable;

/**
 * Only ever constructed with values the enumeration posture permits disclosing
 * (spec §7.1). Under strict posture the shaper passes nulls.
 */
final readonly class RetryPolicy
{
    public function __construct(
        public ?int $attemptsRemaining,
        public ?DateTimeImmutable $lockedUntil,
    ) {}
}
```

Create `src/Kernel/Screen/ScreenSpec.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

final readonly class ScreenSpec
{
    /**
     * @param list<FactorOption>        $offeredFactors
     * @param list<FieldSpec>           $fields
     * @param array<string, mixed>|null $challengePayload
     * @param list<string>              $errors
     */
    public function __construct(
        public AuthStep $step,
        public array $offeredFactors,
        public array $fields,
        public ?array $challengePayload,
        public array $errors,
        public ?RetryPolicy $retry,
    ) {}
}
```

- [ ] **Step 4: Run to verify tests pass**

Run: `composer test && composer stan`
Expected: PASS (2 new tests), no PHPStan errors

- [ ] **Step 5: Commit**

```bash
git add src/Kernel/Screen tests/Kernel/Screen
git commit -m "feat: add immutable screen specification value objects"
```

---

## Task 10: Enumeration posture response shaping

The last kernel component and the one that makes strict mode testable rather than aspirational.

**Files:**
- Create: `src/Kernel/Enumeration/Outcome.php`, `src/Kernel/Enumeration/ErrorShaper.php`
- Test: `tests/Kernel/Enumeration/ErrorShaperTest.php`

**Interfaces:**
- Consumes: `EnumerationPosture` (Task 6), `ScreenSpec`, `AuthStep`, `RetryPolicy` (Task 9)
- Produces: `Outcome` enum; `ErrorShaper::shape(ScreenSpec $spec, Outcome $outcome, EnumerationPosture $posture): ScreenSpec`

- [ ] **Step 1: Write the failing test**

Create `tests/Kernel/Enumeration/ErrorShaperTest.php`:

```php
<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\ErrorShaper;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\FieldSpec;
use Fissible\Vouch\Kernel\Screen\RetryPolicy;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;

function identifyScreen(): ScreenSpec
{
    return new ScreenSpec(
        step: AuthStep::Identify,
        offeredFactors: [],
        fields: [new FieldSpec('identifier', 'email', 'username', maxLength: null)],
        challengePayload: null,
        errors: [],
        retry: new RetryPolicy(attemptsRemaining: 3, lockedUntil: null),
    );
}

it('produces identical output for known and unknown identifiers under strict posture', function (): void {
    $shaper = new ErrorShaper();

    $known = $shaper->shape(identifyScreen(), Outcome::IdentifierKnown, EnumerationPosture::Strict);
    $unknown = $shaper->shape(identifyScreen(), Outcome::IdentifierUnknown, EnumerationPosture::Strict);

    expect($unknown->errors)->toBe($known->errors)
        ->and($unknown->step)->toBe($known->step)
        ->and($unknown->fields)->toEqual($known->fields);
});

it('withholds retry state under strict posture', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::IdentifierUnknown,
        EnumerationPosture::Strict,
    );

    expect($shaped->retry)->toBeNull();
});

it('discloses that an account does not exist under friendly posture', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::IdentifierUnknown,
        EnumerationPosture::Friendly,
    );

    expect($shaped->errors)->toBe(['No account matches that identifier.']);
});

it('keeps retry state under friendly posture', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::IdentifierUnknown,
        EnumerationPosture::Friendly,
    );

    expect($shaped->retry?->attemptsRemaining)->toBe(3);
});

it('gives the same message for a bad credential and an unknown identifier under strict posture', function (): void {
    $shaper = new ErrorShaper();

    $bad = $shaper->shape(identifyScreen(), Outcome::CredentialRejected, EnumerationPosture::Strict);
    $unknown = $shaper->shape(identifyScreen(), Outcome::IdentifierUnknown, EnumerationPosture::Strict);

    expect($bad->errors)->toBe($unknown->errors);
});

it('always discloses a lockout, because withholding it is useless and hostile', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::Locked,
        EnumerationPosture::Strict,
    );

    expect($shaped->errors)->toBe(['Too many attempts. Try again later.']);
});
```

The lockout carve-out is deliberate: a locked account is already observable through timing and repeated failure, so hiding it costs a legitimate user real confusion while telling an attacker nothing they cannot already infer.

- [ ] **Step 2: Run to verify failure**

Run: `vendor/bin/pest tests/Kernel/Enumeration`
Expected: FAIL with `Class "Fissible\Vouch\Kernel\Enumeration\Outcome" not found`

- [ ] **Step 3: Write the outcome enum**

Create `src/Kernel/Enumeration/Outcome.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Enumeration;

/**
 * What actually happened, before posture filtering. Never serialised to a
 * response — ErrorShaper is the only consumer.
 */
enum Outcome: string
{
    case IdentifierKnown = 'identifier_known';
    case IdentifierUnknown = 'identifier_unknown';
    case CredentialRejected = 'credential_rejected';
    case Locked = 'locked';
}
```

- [ ] **Step 4: Write the shaper**

Create `src/Kernel/Enumeration/ErrorShaper.php`:

```php
<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Enumeration;

use Fissible\Vouch\Kernel\Screen\RetryPolicy;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;

final class ErrorShaper
{
    private const UNIFORM = 'Check your email to continue.';

    public function shape(
        ScreenSpec $spec,
        Outcome $outcome,
        EnumerationPosture $posture,
    ): ScreenSpec {
        if ($outcome === Outcome::Locked) {
            return $this->withErrors($spec, ['Too many attempts. Try again later.'], $spec->retry);
        }

        if ($posture === EnumerationPosture::Strict) {
            // One message, one shape, regardless of what actually happened.
            // Retry state is withheld because a differing attempt counter is
            // itself an oracle for whether the account exists.
            return $this->withErrors($spec, [self::UNIFORM], null);
        }

        $errors = match ($outcome) {
            Outcome::IdentifierUnknown => ['No account matches that identifier.'],
            Outcome::CredentialRejected => ['That credential was not accepted.'],
            Outcome::IdentifierKnown => [],
            Outcome::Locked => [],
        };

        return $this->withErrors($spec, $errors, $spec->retry);
    }

    /**
     * @param list<string> $errors
     */
    private function withErrors(
        ScreenSpec $spec,
        array $errors,
        ?RetryPolicy $retry,
    ): ScreenSpec {
        return new ScreenSpec(
            step: $spec->step,
            offeredFactors: $spec->offeredFactors,
            fields: $spec->fields,
            challengePayload: $spec->challengePayload,
            errors: $errors,
            retry: $retry,
        );
    }
}
```

- [ ] **Step 5: Run to verify tests pass**

Run: `composer test && composer stan`
Expected: PASS (6 new tests), no PHPStan errors

- [ ] **Step 6: Run the full mutation pass**

Run: `composer mutate`
Expected: MSI ≥ 85, covered MSI ≥ 95. Address any escaped mutants with tests before committing.

- [ ] **Step 7: Raise the MSI floor**

Edit `infection.json5` and set `minMsi` to the achieved value rounded down to the nearest whole number, so the floor ratchets rather than drifting.

- [ ] **Step 8: Commit**

```bash
git add src/Kernel/Enumeration tests/Kernel/Enumeration infection.json5
git commit -m "feat: shape auth errors by enumeration posture"
```

---

## Task 11: Capture the kernel API surface snapshot

Phase 1's exit criterion and the input to the spec §8.1 extraction trigger: extraction happens when this snapshot survives a full minor cycle unchanged.

**Files:**
- Create: `docs/kernel-api-surface.md`, `tests/Arch/ApiSurfaceTest.php`

**Interfaces:**
- Consumes: every public class from Tasks 2–10
- Produces: a committed snapshot and a test that fails when it drifts

- [ ] **Step 1: Write the surface test**

Create `tests/Arch/ApiSurfaceTest.php`:

```php
<?php

declare(strict_types=1);

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

it('matches the committed public API surface', function (): void {
    $root = __DIR__ . '/../../src/Kernel';
    $entries = [];

    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));

    foreach ($files as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $relative = str_replace($root . '/', '', $file->getPathname());
        $class = 'Fissible\\Vouch\\Kernel\\'
            . str_replace(['/', '.php'], ['\\', ''], $relative);

        if (! class_exists($class) && ! interface_exists($class) && ! enum_exists($class)) {
            continue;
        }

        $reflection = new ReflectionClass($class);

        foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            if ($method->getDeclaringClass()->getName() !== $class) {
                continue;
            }

            $entries[] = sprintf('%s::%s', $class, $method->getName());
        }
    }

    sort($entries);

    $snapshotPath = __DIR__ . '/../../docs/kernel-api-surface.md';
    $expected = trim((string) file_get_contents($snapshotPath));
    $actual = trim(implode("\n", $entries));

    expect($actual)->toBe(
        $expected,
        "Kernel public API changed. If intentional, update docs/kernel-api-surface.md "
        . "and note the change — the §8.1 extraction trigger requires a full minor "
        . "cycle with no breaking change to this surface.",
    );
});
```

- [ ] **Step 2: Generate the snapshot deterministically**

Create `bin/kernel-api-surface.php`:

```php
<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

$root = __DIR__ . '/../src/Kernel';
$entries = [];

$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));

foreach ($files as $file) {
    if (! $file->isFile() || $file->getExtension() !== 'php') {
        continue;
    }

    $relative = str_replace($root . '/', '', $file->getPathname());
    $class = 'Fissible\\Vouch\\Kernel\\' . str_replace(['/', '.php'], ['\\', ''], $relative);

    if (! class_exists($class) && ! interface_exists($class) && ! enum_exists($class)) {
        continue;
    }

    foreach ((new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        if ($method->getDeclaringClass()->getName() !== $class) {
            continue;
        }

        $entries[] = sprintf('%s::%s', $class, $method->getName());
    }
}

sort($entries);

echo implode("\n", $entries), "\n";
```

Run:
```bash
php bin/kernel-api-surface.php > docs/kernel-api-surface.md
```

The generator and the test share their traversal logic deliberately — if they ever disagree, the test fails, which is the desired behaviour.

- [ ] **Step 3: Run to verify it passes**

Run: `vendor/bin/pest tests/Arch`
Expected: PASS

- [ ] **Step 4: Run the entire suite one final time**

Run: `composer test && composer stan && composer mutate`
Expected: all green

- [ ] **Step 5: Update PROJECT.md**

Mark Phase 1 tasks 1–11 as Complete in the table, and replace the "Session handoff notes" section with what was finished, what Phase 2 starts with, and any decision that came up during implementation.

- [ ] **Step 6: Commit**

```bash
git add docs/kernel-api-surface.md tests/Arch/ApiSurfaceTest.php \
        bin/kernel-api-surface.php PROJECT.md
git commit -m "chore: capture kernel public API surface snapshot"
```

---

## Phase 1 Exit Criteria

- [ ] `composer test` green — arch boundary, API surface, and all unit tests
- [ ] `composer stan` clean at level 9
- [ ] `composer mutate` at or above the committed MSI floor
- [ ] `src/Kernel` has zero dependencies beyond `php` and `psr/clock`
- [ ] `docs/kernel-api-surface.md` committed
- [ ] PROJECT.md handoff notes updated

Phase 2 planning starts only after all six hold.
