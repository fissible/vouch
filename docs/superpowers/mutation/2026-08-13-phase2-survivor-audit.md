# Phase 2.3 — Non-kernel mutation gate: survivor audit

**Status: IN PROGRESS. No floor may be set until this is complete.**

## Fixed scope and exclusions

Fixed in `composer.json` **before** the first run and not to be narrowed afterwards:

- **Scope:** `Fissible\Vouch`
- **Ignored:** `Fissible\Vouch\Kernel` — already gated by `mutate:msi` / `mutate:covered` at 80 / 95
- **Nothing else excluded.** Models, exceptions and value objects are all in scope.

## Baseline runs (parallel) — NOT usable as floors

| Pass | Score | Untested | Uncovered | Timeout | Tested | Duration |
|---|---|---|---|---|---|---|
| full | 67.22% | 323 | 169 | 137 | 872 | 1,272s |
| covered-only | 71.08% | 380 | — | 49 | 885 | 995s |

```bash
vendor/bin/pest --mutate --class="Fissible\Vouch" --ignore="Fissible\Vouch\Kernel" --parallel
vendor/bin/pest --mutate --class="Fissible\Vouch" --ignore="Fissible\Vouch\Kernel" --covered-only --parallel
```

**Why these are not floors.** The covered-only pass reports MORE untested mutants than the
full pass (380 vs 323) while its timeouts fall from 137 to 49 — the two runs disagree about
individual mutants. Six to nine percent of each run is in an indeterminate timeout state:
neither killed nor confirmed surviving. A floor drawn from these would fail on re-run for
reasons unrelated to test quality, and the first response would be to lower it.

**`--parallel` emits no per-mutation detail**, only progress dots. Enumeration requires
non-parallel runs, which are far slower (Enrollment alone: 659s for 45 mutations).

## Audit — `Fissible\Vouch\Enrollment` (complete)

45 mutations, 25 untested, 7 uncovered, 13 tested. Score 28.89%.

### Equivalent — no behaviour a test should assert

| Location | Mutation | Disposition |
|---|---|---|
| `EnrollmentRefused:32` ×6 | Concat on the human-readable message | Equivalent. Mutating message prose changes no behaviour; asserting exact copy would make the message unchangeable. |
| `EnrollmentRefused:25` ×3 | Exception code `0`, increment/decrement | Equivalent in practice. Vouch never reads the code; callers match on the class and the typed `reason`. |

### Real gaps — must be closed before a floor is set

| Location | Mutation | Why it matters |
|---|---|---|
| `EnrollmentGuard:146` | `errorInfo[1]` index | **Security-relevant.** Index 1 is the driver code; index 0 is SQLSTATE. Mutating it breaks contention classification, and SQLSTATE alone cannot distinguish contention from a missing table on MySQL or SQLite. |
| `EnrollmentGuard:151` | `$driverCode === 5` | **Security-relevant.** The SQLite busy code. A wrong value silently reclassifies contention as a fatal error, or worse the reverse. |
| `EnrollmentGuard:152` | `default => false` | **Security-relevant.** The fail-loud default for an unrecognised driver. Mutating it to `true` would classify every error on a new engine as contention — "safe to retry" advice for a schema fault. |
| `EnrollmentGuard:92` | `RemoveMethodCall` on `boundTheWait()` | Removing the lock-wait bound is undetected; an unbounded wait hangs a request thread. |
| `EnrollmentGuard:179` | `max(1, ...)` floor | A zero or negative wait changes behaviour and nothing notices. |
| `EnrollmentGuard:185` | `$seconds * 1000` | Unit conversion for SQLite's `busy_timeout` (milliseconds). Wrong unit means a 5ms or 5000s wait. |
| `EnrollmentGuard:97` | `insertOrIgnore` call | The lock claim itself. |

**This independently rediscovered a gap the Task 6 review had already recorded** — that
`isLockContention()`'s true-positive path is untested — and found three more lines of the
same classifier alongside it. That is the gate doing its job before any floor exists.

## Re-measurement after closing the Enrollment gaps

Commit `ddf6724`. Same command, same fixed scope, non-parallel:

| | Before | After |
|---|---|---|
| Score | 28.89% | **71.11%** |
| Untested | 25 | 13 |
| Uncovered | 7 | 0 |
| Tested | 13 | 32 |
| Duration | 659.30s | 86.01s |

**Every `EnrollmentGuard` survivor is killed except one.** All thirteen remaining
untested mutants but that one are in `EnrollmentRefused`, on exception-message prose
(lines 32 and 47) and the exception code (line 25) — the mutations already
dispositioned equivalent, plus the `contended()` message which is the same category.

### The one survivor that is neither closed nor equivalent

`EnrollmentGuard:97`, `RemoveMethodCall` — deleting the `lockForUpdate()` select.

This is **driver-conditional, and the SQLite leg structurally cannot kill it.** The
method's own docblock says why: on SQLite `lockForUpdate` compiles to a bare SELECT
and does nothing, because serialization there comes from the database-level write
lock `insertOrIgnore` already took. On MySQL and Postgres that select IS the
serialization. So the mutant is genuinely equivalent on the engine the default suite
runs, and genuinely lethal on the other two.

Disposition: **deferred to the cross-engine matrix**, not written off. It is the one
survivor whose verdict depends on which engine the gate runs against, which is worth
recording as a property of the gate rather than a defect in the tests.

### Two things NOT concluded from this run

- **The 7.7× duration drop is not attributed to the change.** More coverage should
  make a mutation run slower, not faster, and nothing in the diff shortens the
  covering test set. The likeliest explanation is contention for the machine during
  the first run. Recorded as unexplained rather than claimed as a win.
- **The timeouts are still unaccounted for.** Neither Enrollment run reported a
  single timeout, before or after. So the 137 / 49 timeouts of the full-scope passes
  live in other namespaces, and the leading suspect narrows to the remaining
  candidates — `RecoveryCodeFactor`'s up-to-ten bcrypt comparisons above all.

## Remaining work

1. **Timeouts** — identify and bound or explicitly disposition the 137 / 49 timeout
   mutants. Ruled out of `Enrollment`; hunt them in the remaining namespaces.
2. **Enumerate and audit** the remaining namespaces non-parallel: `Factors` (running),
   `Flow`, `Http`, `Recovery`, `Sessions`, `Attempts`, `Models`, `Secrets`, `Support`,
   `Persistence`, `Tenancy`, `Console`, `Notifications`, `Contracts`.
3. **Close the real gaps**, then re-run both passes.
4. **Establish floors** at or below the audited, reproducible baseline.
5. **Commit** commands, reports, dispositions, counts and floors together.
