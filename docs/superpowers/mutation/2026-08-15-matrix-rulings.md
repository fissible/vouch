# The four matrix-required rows, run on MySQL 8 and Postgres 16

Blocker 1 is discharged. Three of the four rows were **misclassified** and are
equivalent on every supported engine; the fourth is real, was killed, and
exposed a test gap covering the commoner of its two production paths.

Run locally against `mysql:8` and `postgres:16` containers, using the same
`VOUCH_TEST_DB` / `DB_*` wiring as CI's `database-matrix` job. Every ruling below
is a measurement, not an inference: each cast or call was actually removed, the
suite actually re-run on each engine, and the result recorded either way.

## The premise that turned out to be false

`2026-08-15-cast-classification.md` sent three `integer` casts to the matrix on
this stated ground:

> SQLite returns integers natively, so removing an `integer` cast is invisible
> here. MySQL and Postgres return numeric strings.

The second sentence is not true on this stack. Probed directly through PDO, with
both emulated and native prepares, on a `bigint` column:

```
mysql  emulate=false -> 10 (int)     pgsql  emulate=false -> 10 (int)
mysql  emulate=true  -> 10 (int)     pgsql  emulate=true  -> 10 (int)
```

PHP 8.4.24, `pdo_mysql` / `pdo_pgsql` / `pdo_sqlite`. All three drivers hand back
a native `int`. There is no engine on which an uncast integer column arrives as a
string, so there is no engine that can decide these rows.

This is now pinned by `it('hands back a PHP int for an integer column with no
cast involved')` in `tests/Database/CastContractTest.php`, which reads through
the query builder so no Eloquent cast can mask the value, and which runs on all
three engines. If a driver upgrade ever changes this, that test fails and all
three rulings below reopen.

## Row-by-row

### `AuthAttempt:42` — `version` → integer · **equivalent**

Cast removed; `tests/Database tests/Concurrency tests/Factors` stayed green on
MySQL and Postgres (345 passed each), including the existing
`expect($attempt->version)->toBeInt()` assertion, confirmed running by name.

The consumer is the CAS at `DatabaseAttemptStore.php:78`,
`->where('version', $attempt->version)`. That is a SQL comparison against an
integer column, which both engines coerce; the cast never enters into it.

### `AuthChallenge:39` — `attempts` → integer · **equivalent**

Phase 2.3b has now given `attempts` its first production writer and threshold:
`DatabaseAuthThrottleStore::recordChallengeFailure()`. The prior stronger
premise — that no consumer existed — is retired.

The ruling remains equivalent for a narrower measured reason. Every security
operation is SQL arithmetic and comparison against the integer column; no
production decision reads `AuthChallenge::$attempts` through Eloquent. The
three-engine premise test now writes and reads an `auth_challenges.attempts`
value through both the raw query builder and the model. All current PDO drivers
return a native int before the cast applies. Removing the cast changes the
model's declared shape but not its runtime value on any supported engine.

The cast is therefore not the control. The atomic SQL update, exact fifth-guess
boundary, terminal `consumed_at` write, and wrong/correct races are tested on
file-backed SQLite, MySQL, and PostgreSQL. A driver upgrade that starts returning
numeric strings reopens this ruling through the raw-value premise test.

### `AuthCredential:57` — `last_used_timestep` → integer · **equivalent**

The row carrying the most alarming rationale, and the one worth being most
careful about retiring. Two independent reasons it does not discriminate:

1. The driver returns an int, as above.
2. Even given a string, the fast path at `TotpFactor.php:231` is
   `$matched <= $credential->last_used_timestep`. PHP 8 compares two numeric
   operands numerically, so `9 <= '10'` is `true` — verified, not assumed. The
   lexicographic ordering the doc feared is a PHP 7 behaviour.

The authoritative replay guard is not this comparison at all. It is the
`last_used_timestep IS NULL OR < :step` predicate at
`DatabaseAttemptStore.php:163-166`, which is evaluated **by the engine** against
an integer column and is unaffected by any Eloquent cast. The fast path is
explicitly documented as a cost optimisation over that predicate.

No replay window opens. The row is equivalent.

### `EnrollmentGuard:97` — `lockForUpdate()` · **KILLED (Postgres)**

Real, and the existing suite could not see it. All four pre-existing contention
tests still passed with the call removed, on both engines.

The reason is that `acquire()` has two paths and they were only testing one:

- **No lock row yet** — `insertOrIgnore` creates it and holds a lock until
  commit. A second writer blocks on the duplicate key and is refused *by the
  insert*, never reaching the select. Every existing test starts here, so
  `lockForUpdate` is never load-bearing in any of them.
- **Lock row already committed** — `insertOrIgnore` is a no-op. On Postgres
  `ON CONFLICT DO NOTHING` takes no lock and returns immediately, so
  `lockForUpdate` is the only thing serializing two writers.

Nothing ever deletes from `auth_enrollment_locks` — the guard only inserts, and
`vouch:prune` does not touch the table. So the row survives a subject's first
enrollment and **every enrollment after it takes the second path**. The untested
path was the common one.

`it('serializes a re-enrollment, where the lock row already exists')` in
`tests/Concurrency/EnrollmentContentionTest.php` seeds the lock row committed,
then races. Verified both ways:

| Engine | `lockForUpdate` present | removed |
|---|---|---|
| SQLite (file) | passes | passes — no-op there by design |
| MySQL 8 | passes | passes |
| Postgres 16 | passes | **fails** — mutant killed |

MySQL survives because InnoDB takes a shared lock on the conflicting index
record during `INSERT IGNORE`, which blocks against the holder's exclusive lock.
The 2.8s runtime under the mutant is the lock-wait bound elapsing — MySQL refuses
via the insert, not the select. Postgres takes no such lock, which is what makes
it the deciding engine.

`EnrollmentGuard`'s docblock said "on MySQL and Postgres the lockForUpdate is
what serializes". That is now corrected in place to describe both paths and which
engine actually depends on the call.

## Also fixed

`tests/Database/CastContractTest.php` inserted the string `'tok-1'` into
`auth_token_assurances.token_id`, an `unsignedBigInteger`. SQLite's dynamic
typing accepted it; MySQL strict mode rejected it outright with
`SQLSTATE[HY000] 1366`. The test landed in `56bb638` and had never run on the
matrix. It was the first failure of this session.

## State after this work

| | |
|---|---|
| SQLite (default suite) | 681 passed · 9 skipped |
| SQLite (file), MySQL 8, Postgres 16 | 347 passed each |
| PHPStan level 9 | clean |

Blocker 1 is closed: 3 rows dispositioned `equivalent` with their shared premise
tested, 1 row killed. Blocker 2 (the 56 provider rows in `upstream-defect/`) is
untouched and remains the only thing between Task 13 and its gate.
