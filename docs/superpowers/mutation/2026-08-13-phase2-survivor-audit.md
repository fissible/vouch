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

## The bcrypt override cannot reach production

Commit `4c6a0ec`-series. Four independent controls, so the barrier survives any one
of them being wrong:

1. Nothing under `src/` or `config/` may write hashing configuration at all — in
   either direction. Choosing a password hashing cost belongs to the host.
2. `Fissible\Vouch\Tests\` is absent from the production autoloader (`autoload-dev`
   only).
3. `orchestra/testbench` stays in `require-dev`, so `TestCase`'s parent class does
   not exist in a production install and the file cannot load even if reached for.
4. `/tests export-ignore` keeps the file out of the distributed archive entirely.

Verified: `git archive HEAD` yields 136 `src/` files and **zero** test files. Probed:
adding a hashing config write to the service provider fails control 1; removing the
export-ignore line fails control 4. The directory scan is guarded by a non-empty
file-count assertion so a mistyped path cannot pass by scanning nothing.

## Irreducible timeouts in the eventual baseline

The four non-terminating loop mutants are a **stable property of the tool**, not
survivors. They must be carried in the baseline as a named constant — a floor
expressed as "score ≥ X with 4 known-irreducible timeouts" — and never normalised
away by counting them as killed or by excluding their files from scope.

| Location | Mutation |
|---|---|
| `RecoveryCodeFactor:131` | `PostIncrementToPostDecrement` |
| `RecoveryCodeFactor:239` | `PostIncrementToPostDecrement` |
| `OtpFactor:415` | `PostIncrementToPostDecrement` |
| `TotpFactor:266` | `PostDecrementToPostIncrement` |

## Factors group 1 — `TotpFactor` (partial)

Commit `22a50da`. TotpFactor **62.41% → 66.92%**; suite 463 → 482.

Closed: constructor boundaries for period, digits and window (both sides of each);
the empty-issuer refusal; the period, digits and window defaults; enroll()'s label
contract; the `replace === true` strictness together with the original credential
surviving a refusal; both no-credential paths in verify(); and the pre-epoch
timestep guard.

**`TotpFactor:267` `PlusToMinus` is dispositioned equivalent by symmetry.** The loop
is `for ($offset = $this->window; $offset >= -$this->window; $offset--)` and the body
computes `$currentStep + $offset`. Because the window is symmetric, negating the
offset maps the set of visited steps onto itself. No test can distinguish the two,
and none should try.

Still open in `TotpFactor`: message-string concatenation (group 3, pending the
protocol-value check), and the remaining verify() predicates at lines 203 and 218.

## Factors group 1 — complete for four drivers

| Driver | Before | After |
|---|---|---|
| `PasswordFactor` | 88.89% | **93.33%** (zero untested) |
| `RecoveryCodeFactor` | 62.37% | **80.65%** |
| `TotpFactor` | 62.41% | **74.05%** |
| `OtpFactor` | 69.87% | **74.36%** |

Suite 463 → 499.

### Dispositioned equivalent, with reasons

- `TotpFactor:280` `PlusToMinus` — the drift window is symmetric, so negating the
  offset maps the visited steps onto themselves.
- `TotpFactor:283` `ContinueToBreak` — offsets descend, so steps descend
  monotonically; once one is negative every later one is, and continuing and
  breaking visit the same set.
- `OtpFactor:416` `RemoveStringCast` — PHP concatenates an int identically.

### `RecoveryCodeFactor:240` — closed, not normalised

First recorded as "real but not economically detectable". That was the wrong
call: a mutation floor must not carry a known entropy defect in
authentication-secret generation as an accepted constant.

The mutation turns `random_int(0, $max)` into `random_int(-1, $max)`. PHP reads
`$alphabet[-1]` as the LAST character, so the generator keeps producing
ordinary-looking codes and the only symptom is a bias toward 'Z' — invisible to
any assertion about length, shape or character coverage, and reachable only by a
distribution test that would be flaky by construction.

The fix is an injectable `RandomSource` (`src/Contracts/RandomSource.php`).
Production delegates to `random_int()`; the test double returns its own lower
bound, so drawing from index 0 must yield '0' on every draw and the mutant yields
'Z' on every draw. The tests assert the requested RANGE as well as the output,
since a generator quietly asking for `int(1, $max)` would otherwise still look
self-consistent. Probed both directions; each fails deterministically.

The injection is a seam, and it is pinned: the contract resolves to
`SystemRandomSource` by default, the container-resolved drivers are asserted on
generated OUTPUT rather than wiring (a constructor default would paper over a
broken binding), and the source is checked to return both of its bounds — a
source that never does would relocate the same defect one layer down.

`RecoveryCodeFactor` 80.65% → **81.72%**, zero non-message survivors.

### On the assurance attributes — stated conservatively

An earlier note here claimed that flipping `isMultiFactor`, `userVerified` and
`phishingResistant` would let an emailed code satisfy a hardware-key requirement.
That overstates the present risk and should not stand.

As the system is configured today, recovery evidence is filtered out of
satisfiability by the kernel, and the default assurance vocabulary caps at AAL2 —
so there is no present default path by which these flags issue AAL3. What they
are is a future-proofing gap: the values are hard-coded false because none of
these credentials is multi-factor, user-verifying or phishing-resistant, and
nothing outside TOTP asserted that. The moment an AAL3 rung enters the vocabulary
or the recovery filter changes, an unasserted `false` becomes load-bearing with
no test standing behind it. Worth closing on those grounds, not on a claim of
current exploitability.

### Group 2 — config defaults

Subsumed by group 1. Every constructor default in the namespace (`TotpFactor`
period/digits/window/issuer, `OtpFactor` length/ttl, `RecoveryCodeFactor`
count/length) is externally meaningful — each is part of the package's contract
with a host that configures nothing — and each is now pinned by a test that
constructs the driver with **no** argument for it. Passing the value explicitly
reads the caller's number, not the default; that mistake was made and caught
twice.

### Group 3 — message concatenation: equivalent, precondition verified

13 surviving sites remain, all `Concat*`. The disposition is **equivalent**, and
the three disqualifying conditions were checked rather than assumed:

| Test | Result |
|---|---|
| Protocol value? | No. Every site is an exception message. Nothing built by these concatenations is stored, transmitted, or compared. |
| Exception class contract? | No. `getMessage()` appears **nowhere** in `src/`. Callers match on the exception class and on typed properties (`EnrollmentRefused::$reason`), never on message text. |
| User-visible shaped error? | No. The JSON surface emits only ScreenSpec-derived keys (`screen`, `step`, `fields`, `errors`, `retry`, …). No exception message is read, and neither `AuthFlow` nor `AuthController` catches `Throwable`. |

Every site is a developer-facing diagnostic — `InvalidArgumentException` for host
misconfiguration, `LogicException` for the write-once registry violation. Their
audience is an operator reading a stack trace, and asserting their exact wording
would make the copy unmaintainable while protecting nothing.

Two message branches were promoted OUT of this group because they are not prose:
`UnknownFactor`'s empty-vs-populated ternary (a live conditional separating two
different faults) and its `array_keys()` payload. Both are now tested, and
`UnknownFactor` is at 100%.

`TotpFactor:128` is partially pinned — its test matches the identifying clause,
not the whole sentence, deliberately, so the guard is load-bearing while the
prose stays editable.

### `Fissible\Vouch\Factors` — final

**62.47% → 79.23%.** 4 timeouts, all irreducible non-terminating loop mutants.
Nine non-message survivors remain, every one dispositioned equivalent with a
stated reason:

| Location | Mutation | Why equivalent |
|---|---|---|
| `TotpFactor:280` | `PlusToMinus` | Symmetric window: negating the offset maps visited steps onto themselves |
| `TotpFactor:283` | `ContinueToBreak` | Offsets descend, so once a step is negative every later one is |
| `OtpFactor:178` | `RemoveArrayItem` | Drops `'secret' => null`, which is the column default |
| `OtpFactor:391` | `InstanceOfToTrue` | Guards a branch the source documents as unreachable |
| `OtpFactor:421` | `RemoveStringCast` | PHP concatenates an int identically |
| `FactorResult:33` | `UnwrapArrayValues` | A variadic is already a list; `array_values` is a no-op |

## Schema-conditional equivalence

A survivor whose equivalence depends on a fact outside the file needs that fact
verified and then held true, not assumed once.

**`AuthFlow` — `RemoveArrayItem` on `'version' => 1`.** The attempt's version is
the compare-and-swap epoch, so removing it from the insert looks alarming. It is
not, under the current schema: the column carries `->default(1)`, and the
compiled DDL was checked on every supported engine rather than inferred from
Laravel's API.

| Engine | Compiled column |
|---|---|
| MySQL | `` `version` bigint unsigned not null default '1' `` |
| Postgres | `version" bigint not null default '1'` |
| SQLite | `version" integer not null default '1'` |

Disposition: **equivalent, conditional on the schema.** The explicit assignment
stays — it documents the CAS invariant at the point of creation, where a reader
looks for it — but it is a documented redundancy rather than the mechanism.

The condition is now pinned by a test that inserts an attempt row **without** the
column and asserts it reads back as 1, so it reads the database default rather
than anything the application supplied. Probed: removing `->default(1)` from the
migration fails it. If a later migration drops or changes that default, the
equivalence would silently become a real defect; instead the test fails.

This is the pattern to reuse whenever a survivor is equivalent "because of
something elsewhere": verify the something, then make it a test, then record the
disposition as conditional on it.

## Remaining work

1. ~~**Timeouts**~~ — cause identified and bounded above. Confirm the count reaches
   zero on the full-scope re-run.
2. **Enumerate and audit** the remaining namespaces non-parallel: ~~`Factors`~~ (done),
   `Flow`, `Http`, `Recovery`, `Sessions`, `Attempts`, `Models`, `Secrets`, `Support`,
   `Persistence`, `Tenancy`, `Console`, `Notifications`, `Contracts`.
3. **Close the real gaps**, then re-run both passes.
4. **Establish floors** at or below the audited, reproducible baseline.
5. **Commit** commands, reports, dispositions, counts and floors together.
