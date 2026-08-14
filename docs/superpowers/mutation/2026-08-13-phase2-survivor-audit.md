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

### Why the duration fell 7.7×

A killed mutant stops at the first failing test; a surviving one runs its entire
covering set to the end. Untested went 25 → 13 and tested went 13 → 32, so most of
the run stopped paying for full-suite executions.

**Mutation-run duration is therefore dominated by survivors, not by coverage.**
Closing gaps makes the gate cheaper, which is the opposite of the usual intuition
and worth knowing before anyone tries to make the gate affordable by narrowing it.

## Timeouts: cause identified and bounded

The Factors slice was killed mid-run inside `RecoveryCodeFactor` — the suspect
itself. The cause is not a hang. It is bcrypt cost:

`RecoveryCodeFactor` verifies a submitted code against up to ten stored digests, so
its covering tests perform up to ten real bcrypt rounds each. At the framework
default those 14 tests cost **35.4 seconds**, and a mutation run pays that per
mutant. Combined with the survivor effect above, a single surviving mutant in that
file costs more than half a minute.

**Fix:** `hashing.bcrypt.rounds` is pinned to 4 in `tests/TestCase.php`, the test
environment only.

| | Before | After |
|---|---|---|
| `--filter=RecoveryCode` (14 tests) | 35.38s | **0.67s** |
| Full suite (463 tests) | 74.37s | **5.01s** |

This weakens nothing asserted. The cost factor is not part of any behaviour under
test — the equalization tests count hasher calls rather than measure elapsed time,
precisely so they do not depend on how expensive a round is — and bcrypt verifies a
digest at whatever cost it was written with. Production cost stays with the host
application. All 463 tests still pass.

Neither Enrollment run reported a single timeout, so the 137 / 49 timeouts of the
baseline passes were concentrated in the bcrypt-bound namespaces. The full-scope
re-run at the end of this audit is what will confirm the count reaches zero.

## Audit — `Fissible\Vouch\Factors` (enumerated; dispositions in progress)

127 untested, 40 uncovered, 4 timeout, 274 tested. Score 62.47%, 268.59s.
Full enumeration: `2026-08-13-factors-survivors.md`.

### All four timeouts dispositioned: non-terminating mutants

| Location | Mutation | Loop |
|---|---|---|
| `RecoveryCodeFactor:131` | `PostIncrementToPostDecrement` | `for ($i = 0; $i < $this->count; $i++)` |
| `RecoveryCodeFactor:239` | `PostIncrementToPostDecrement` | `for ($i = 0; $i < $this->length; $i++)` |
| `OtpFactor:415` | `PostIncrementToPostDecrement` | `for ($i = 0; $i < $this->length; $i++)` |
| `TotpFactor:266` | `PostDecrementToPostIncrement` | `for ($offset = $this->window; $offset >= -$this->window; $offset--)` |

Every one reverses a loop counter against its own termination condition, so the
mutated program never halts. **No test can kill a non-halting mutant** — the run
either times out or never returns. Timeout is the correct verdict here, not a
defect and not a gap, and these four are dispositioned as such rather than
counted against a floor.

That, with the bcrypt bound above, closes the timeout question: the large counts
were bcrypt cost, and the irreducible remainder is loop-counter non-termination.

### Survivor classes still to disposition

The 127 fall into recognisable groups, none of them ruled on yet:

- **`Concat*` on prompt, label and message strings** (driver lines 54–70, 136,
  199, 376; `FactorRegistry:29`) — the same category already dispositioned
  equivalent in `EnrollmentRefused`, pending confirmation that none of these
  strings is a protocol value rather than display copy.
- **TOTP drift-window arithmetic** (`TotpFactor` 57–59, 70, 79, 267–269) — the
  window bounds. Real behaviour; likely real gaps.
- **Verification and enrollment predicates** (`TotpFactor` 126–150, 201–218;
  `OtpFactor` 130, 263–275, 329–331, 386; `PasswordFactor:72`;
  `RecoveryCodeFactor` 165, 210–212) — real behaviour; likely real gaps.
- **Config-default integers** (`OtpFactor` 54–55, 68; `RecoveryCodeFactor`
  54–55, 67; `TotpFactor` 58) — defaults with no assertion behind them.

## Remaining work

1. ~~**Timeouts**~~ — cause identified and bounded above. Confirm the count reaches
   zero on the full-scope re-run.
2. **Enumerate and audit** the remaining namespaces non-parallel: `Factors` (running),
   `Flow`, `Http`, `Recovery`, `Sessions`, `Attempts`, `Models`, `Secrets`, `Support`,
   `Persistence`, `Tenancy`, `Console`, `Notifications`, `Contracts`.
3. **Close the real gaps**, then re-run both passes.
4. **Establish floors** at or below the audited, reproducible baseline.
5. **Commit** commands, reports, dispositions, counts and floors together.
