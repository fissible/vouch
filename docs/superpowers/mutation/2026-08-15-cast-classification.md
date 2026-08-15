# Remaining cast rows — classified by engine observability

Determined per row, not assumed. The test is what an **uncast** column returns
on SQLite: if it differs from the cast type, the row is provable here; if SQLite
already returns the right PHP type, only MySQL and Postgres can decide it.

## SQLite-observable (13 rows) — provable here, tests still to write

Uncast, a `datetime` column returns a **string** and a json column returns a
**JSON string** on every engine including SQLite, so a typed read-back
discriminates. The pattern is already proven by the grace-deadline and `amr`
assertions in `CastContractTest`.

| Rows | Cast |
|---|---|
| `AuthSession` 39, 41 | `last_factor_at`, `revoked_at` → datetime |
| `AuthChallenge` 41 | `consumed_at` → datetime |
| `AuthIdentifier` 37 | `verified_at` → datetime |
| `AuthTokenAssurance` 35 | `issued_at` → datetime |
| `AuthLinkRequest` 31, 32 | `proven_at`, `expires_at` → datetime |
| `AuthCredential` 56, 58 | `last_used_at`, `disabled_at` → datetime |
| `AuthConnection` 43, 44 | `claim_mappings`, `jit_rules` → array |
| `AuthFederatedIdentity` 34 | `claims` → array |
| `AuthLinkRequest` 30 | `AlwaysReturnEmptyArray` on `casts()` — discharged by any of that model's two rows above |

`revoked_at` is the one with direct security weight: `ValidatesVouchSession` and
the prune retention window both compare against it, and an uncast string
comparison against a date is lexicographic.

## MATRIX-REQUIRED (2 rows) — SUPERSEDED, both equivalent

> **Retracted 2026-08-15 by `2026-08-15-matrix-rulings.md`.** The premise below
> is false. Both rows were run on MySQL 8 and Postgres 16 with the cast removed
> and neither engine can decide them: `pdo_mysql`, `pdo_pgsql` and `pdo_sqlite`
> all return a native PHP `int` for an integer column on PHP 8.4. The same
> applies to `AuthAttempt:42`. Three of the four "matrix-required" rows are
> `equivalent`; only `EnrollmentGuard:97` was real, and it was killed. Read the
> rulings doc rather than the table below.

SQLite returns integers natively, so removing an `integer` cast is invisible
here. MySQL and Postgres return numeric strings.

| Row | Cast | Why it matters |
|---|---|---|
| `AuthChallenge:39` | `attempts` → integer | The OTP attempt counter. Uncast, increments and threshold comparisons become string operations. |
| `AuthCredential:57` | `last_used_timestep` → integer | The TOTP replay guard. `last_used_timestep < :step` as a string comparison orders "10" before "9". |

Both join `AuthAttempt:42` (`version`) and `EnrollmentGuard:97` in the
matrix-required set. Same discriminating proof: assert the typed behaviour on
MySQL and PostgreSQL, remove the cast, confirm the engine-specific test fails.

**`last_used_timestep` deserves emphasis** — a string-ordered replay guard would
accept timestep 9 after 10, which is a replay window opening on a lexicographic
accident. It cannot be demonstrated on SQLite.

## Status

All 15 classified. 13 provable here and awaiting tests; 2 matrix-required. None
is ruled equivalent, and none is discharged by this document — classification
records what evidence each needs, not that it has it.
