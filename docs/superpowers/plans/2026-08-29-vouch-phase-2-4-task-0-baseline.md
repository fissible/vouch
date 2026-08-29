# 2.4 Task 0 — baseline and dependency boundary

**Recorded:** 2026-08-29
**Starting SHA:** `d6af8dcaa1be9577d9405747c83b6d14d0452617`
**Gate:** no source changes until these are written down. None were made. The only
untracked path is this document itself — recorded so a later "clean tree" check does not
read it as drift.

Every figure below was measured, not inferred, and then independently re-derived by a
second reviewer. Where a claim could have been taken from a constraint file instead of
run, the run is what is recorded.

**Environment.** PHP 8.4.24 (cli, NTS); Composer 2.10.2; MySQL via `mysql:8`; PostgreSQL
via `postgres:16`.

**Exact commands.**

```sh
vendor/bin/pest                                    # SQLite, default
VOUCH_TEST_DB=mysql DB_HOST=127.0.0.1 DB_PORT=33306 DB_DATABASE=vouch_test \
  DB_USERNAME=root DB_PASSWORD=password vendor/bin/pest
VOUCH_TEST_DB=pgsql DB_HOST=127.0.0.1 DB_PORT=55432 DB_DATABASE=vouch_test \
  DB_USERNAME=postgres DB_PASSWORD=password vendor/bin/pest
vendor/bin/phpstan analyse --no-progress --memory-limit=1G
```

## Suite baseline

| Engine | Result | Assertions |
|---|---|---|
| SQLite (default, file-backed via `tests/bootstrap.php`) | 1,478 passed, 1 skipped | 4,696 |
| MySQL 8 | 1,477 passed, 2 skipped | 4,696 |
| PostgreSQL 16 | 1,478 passed, 1 skipped | 4,700 |

PHPStan level 9 over `src` and `tests`: clean. 24 **tracked migration files** — a file
count, not a captured `migrate:status`.

The counts differ by engine on purpose, and the decomposition matters more than the
totals, because a later task comparing only totals could "fix" them into agreement and
break something:

- MySQL's extra skip is `BoundedLockWaitTest`'s PostgreSQL lock-timeout unit, skipped with
  "PostgreSQL lock_timeout units are only available on PostgreSQL" (8 passed / 1 skipped /
  26 assertions on MySQL; 9 passed / 28 assertions on PostgreSQL). The other skip present
  on both non-SQLite engines is SQLite-only.
- PostgreSQL's four extra assertions over SQLite are **two** from that PostgreSQL-only
  test and **two** from `ThrottleSchemaTest` metadata assertions, which run on MySQL as
  well. MySQL's two extra metadata assertions are exactly offset by its skipped
  PostgreSQL-only test, which is why its total matches SQLite's.

An earlier draft of this record said only "engine-specific tests" account for the four.
That was a rationalisation that happened to be half right, and it is replaced above with
the measured decomposition — the point of a baseline is that the next person can check it,
not that it sounds plausible.

## Compatibility range

Vouch requires PHP `^8.4` and `illuminate/* ^13.0`.

`laravel/sanctum` is **not installed**, transitively or otherwise. Its current release
v4.3.3 declares `illuminate/* ^11.0|^12.0|^13.0` and dev-requires
`orchestra/testbench ^9.15|^10.8|^11.0`; Vouch is on testbench `^11.0`.

That combination is not merely constraint-compatible, it resolves. A dry run against the
committed lock reports `1 install, 0 updates, 0 removals — Installing laravel/sanctum
(v4.3.3)` with no conflicts. This matters because Task 1's gate is a contract test against
**real** Sanctum; had Laravel 13 support been missing, Task 1 would have been blocked
rather than merely harder, and the whole plan order would need revisiting.

The dry run was reverted; `composer.json` and `composer.lock` are unchanged at the
starting SHA.

## Sanctum dependency stance — recorded, not retaken

The plan's Task 0 says to "decide and document" this. It was decided during the design
and ratified in contract addendum §10: a `TokenIssuer` contract with a Sanctum driver,
`suggest` never `require`, an `UnconfiguredTokenIssuer` that throws with a message naming
what to bind. This matches the Task 6 stance on `spatie/laravel-permission` and the
existing `OtpDelivery` / `DeliveryEconomics` / `CaptchaVerifier` pattern.

Recorded here so Task 1 starts from the decision rather than reopening it. The package
must not fail to boot merely because Sanctum is absent; it fails only when a host enables
the Sanctum issuer without installing it.

## `auth_token_assurances` consumers — verified, not assumed

The addendum claims this table is "a model and fixture surface only", and that claim is
what licenses drop-and-recreate. Verified by enumerating every reference in `src/`,
`tests/`, `database/`, `routes/` and `config/`:

- `src/Models/AuthTokenAssurance.php` — the model.
- `database/migrations/2026_08_12_000007_create_auth_token_assurances_table.php`.
- `src/Factors/Drivers/OtpFactor.php:116` — a **comment** explaining why credential IDs
  are preserved. Not a read.
- Tests only: `PoliciesAndTokenAssurancesTest`, `CredentialRecoveryTest` (asserts the
  table is empty), `CastContractTest`, `IdentifierVerificationTest` (asserts empty),
  `OtpFactorTest` (comment).

**No runtime authorization consumer exists in `src/`.** The single non-model `src/` hit is
a comment. The addendum's claim holds.

The scope limit stands and is not softened by this verification: it covers Vouch-owned
consumers. A host reading this table with raw SQL, a reporting job or a security
integration is invisible from here, and remains an incompatible migration condition to be
stated in the upgrade notes.

## What Task 1 may now assume

- The starting SHA above, with a clean three-engine suite and clean PHPStan.
- Sanctum v4.3.3 installs against Laravel 13 and testbench 11, so the contract test can
  run against the real package rather than a double.
- The schema may be dropped and recreated without losing a Vouch-owned consumer.
- The dependency stance is settled; Task 1 implements it rather than debating it.
