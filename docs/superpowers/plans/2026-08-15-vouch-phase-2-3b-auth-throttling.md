# Vouch Phase 2.3b — Authentication Throttling Implementation Plan

> **For agentic workers:** Execute one task at a time. Write the discriminating test
> first, run the named focused gate, probe the exact control, then commit only the
> listed paths. Never infer cross-engine behavior from SQLite.

**Status:** Dependency-ordered implementation plan, written 2026-08-15. Tasks 1–16
completed 2026-08-16; Task 17 is next. Task 14's delivery-lifecycle design gate is
resolved in the scope amendment.

**Goal:** Complete the missing production email/SMS OTP issuance path, then add
enumeration-safe authentication throttling, challenge-attempt and issuance caps,
posture-safe retry disclosure, bounded identifier lockout, and aggregate observe-mode
reporting without turning shared IP/tenant/global signals into account-lock authority.

**Design authority:**
[`docs/superpowers/specs/2026-08-15-vouch-phase-2-3b-scope-amendment.md`](../specs/2026-08-15-vouch-phase-2-3b-scope-amendment.md).
If this plan and the amendment differ, stop and amend one explicitly; do not choose
whichever version makes the current test pass.

**Tech stack:** PHP 8.4, Laravel 13 / Illuminate 13, Testbench 11, Pest 3,
PHPStan level 9, SQLite file databases, MySQL 8, PostgreSQL 16.

## Effort and critical path

Estimates are engineering time, not elapsed mutation or matrix runtime. They assume
the existing Testbench harness and engine containers work. A failed portability
premise reopens the task that owns it rather than being absorbed into contingency.

| Task | Estimate | Depends on | Parallel after dependency |
|---|---:|---|---|
| 1. Baseline and inherited controls | 1–2 h | — | Yes |
| 2. Required HMAC domains and canonicalization | 6–9 h | 1 | Yes |
| 3. Restoring bounded-lock primitive and EnrollmentGuard correction | 10–14 h | 1 | Yes |
| 4. Declared `RetryPolicy::$retryAfter` kernel amendment | 4–6 h | 1 | Yes |
| 5. Configuration contract and fail-loud validator | 6–8 h | 1 | Yes |
| 6. Four-table persistence shape | 7–10 h | 1, 5 | Yes |
| 7. Auth-specific store contract and result types | 5–7 h | 2, 5, 6 | Yes |
| 8. Scalar counter and identifier-lock store | 10–14 h | 3, 7 | Yes |
| 9. Distinct-subject IP store | 12–18 h | 3, 7 | No — critical path |
| 10. Three-engine contention and rollover matrix | 12–18 h | 8, 9 | No — critical path |
| 11. Error shaping, screens, and wire format | 6–9 h | 4, 7 | Yes |
| 12. Flow preflight, failure counting, lockout, and reset | 14–20 h | 8, 10, 11 | No — critical path |
| 13. Challenge-attempt cap and invalidation | 8–12 h | 7 | Yes |
| 14. Corrective OTP issuance, cap, and 2.3c seam | 16–24 h provisional; re-estimate after design gate | 8, 11, 12, 13 | No |
| 15. Pruning and aggregate observe-mode report | 7–10 h | 6, 8, 9, 14 | No — outbox expiry |
| 16. Container wiring and architecture boundaries | 6–9 h | 11–15 | No |
| 17. Mutation reconciliation and completion matrix | 10–16 h plus runtime | all | No |

Expected engineering effort: **140–206 hours plus any delivery-lifecycle delta**, with
Tasks 2–6 parallelizable. Task 14's range is provisional until its synchronous-
transport/partial-issuance gate is decided. The
critical chain has two prerequisite arms—**1 → 3** and **1 → 5 → 6 → 7**—that join
at **9 → 10 → 12 → 14 → 15 → 16 → 17**. The store, real-engine matrix, and durable
delivery boundary are the schedule risk. That chain is approximately 96–141
engineering hours before the unresolved delivery-lifecycle delta and runtime. Do not
make it cheaper by narrowing the tests.

## Non-negotiable constraints

- Submitted identifiers, not resolved users, own identifier failure state. Known and
  nonexistent identifiers increment identically wherever verification timing is
  equalized.
- The worst-case fixed-boundary online guess target for current six-digit OTP/TOTP
  factors is at most `10^-4` per submitted identifier.
- Only the submitted-identifier dimension may write lock state or produce populated
  `lockedUntil`. Shared dimensions are advisory and ship in observe mode.
- Identifier state commits before best-effort shared state. The two transactions and
  their different units intentionally have no reconciliation invariant.
- IP comes only from `AuthController` via `FlowRequest::clientIp`. The package never
  reads forwarding headers and skips the IP dimension when the value is null.
- Throttle tables contain HMAC digests only. No command, contract, or debug option may
  accept a candidate subject for lookup or emit a per-subject row.
- Database time owns windows and deadlines. Interval SQL comes only from
  `DatabaseTime::deadlineSqlHere()`.
- Shared parent-lock wait is fixed at one second. Verified contention skips that
  shared dimension; unknown drivers and unrelated query failures remain loud.
- Every persistence/concurrency claim runs on file-backed SQLite, MySQL 8, and
  PostgreSQL 16. In-memory SQLite is not concurrency evidence.
- Existing `retry: null`, strict-posture, and lockout architecture tests are rewritten
  to assert measured behavior. They are never deleted to make 2.3b fit.
- `AuditSink` stays unbound. Observe-mode reporting is aggregate operational data, not
  an unaudited substitute.
- Conventional Commits. Stage named paths only; never `git add -A`.

## Verified current seams

These facts were read from the current tree before this plan was written.

| Current fact | Planning consequence |
|---|---|
| `BindingDomain` has only `Session` and `Attempt`; `SessionBinding::for()` accepts one string. | Task 2 adds required throttle domains and unambiguous multi-segment derivation without changing existing session/attempt outputs. |
| Unicode NFC is required by the amendment, but the package has no direct Unicode-normalization dependency. `symfony/string` and its polyfills are present only transitively in the development install; CI does not install `ext-intl`. | Task 2 promotes `symfony/string` to an explicit production requirement and tests the polyfill-compatible path. No implementation may work only because this machine has `ext-intl`. |
| `EnrollmentGuard::boundTheWait()` leaves MySQL and SQLite connection settings changed; its contention test reads the leaked value back. | Task 3 deliberately corrects Phase 2.1 behavior and splits “set during” from “returns while contended” evidence. |
| `RetryPolicy` has exactly `attemptsRemaining` and `lockedUntil`; `FlowResultSerializer` hardcodes retry to null. | Tasks 4 and 11 make the declared kernel amendment and then carry the measured value to the wire. |
| `AuthChallenge::$attempts` is cast but never read or written. | Task 13 gives it its first behavior and re-rules the prior equivalent mutation. |
| `AuthFlow` has two timing-equalizer sites: the missing/unoffered/userless path and the driver's `NoCredential` path. | Task 12 couples each site to identifier state and probes either half independently. |
| Production `AuthFlow` never calls `Factor::challenge()`. Its calls named `challenge()` only build `ScreenSpec`; all actual OTP issuance calls are in driver tests. | This is a post-certification Phase 2.3 correctness defect, not only a missing cap. Task 14 completes email/SMS OTP end to end before it can claim to cap issuance. A cap around no event is vacuous. |
| `OtpFactor::challenge()` refuses ambiguous target selection, commits a challenge row, then calls synchronous delivery on the request path. There is no queue or transaction around the pair. Parent spec §7.1 requires an unknown-identifier decoy that sends nothing and a posture-safe response. | Task 14 may not wire this method into the request unchanged: target-dependent volume state, provider latency, and partial issuance each violate a stated boundary. It must first settle the delivery lifecycle without choosing a credential, sending to all, or turning ambiguity into a public 500. |
| CI's database matrix already runs the full suite on SQLite/MySQL/PostgreSQL. | Each database-sensitive task adds focused local commands, while Task 17 uses the existing full matrix as the completion gate. |

## Dependency graph

```text
1 -> {2 keys/canonicalization, 3 bounded lock wait, 4 kernel retry, 5 config}
5 -> 6 schema
{2, 5, 6} -> 7 store contract
{3, 7} -> {8 scalar store, 9 IP store} -> 10 matrix
{4, 7} -> 11 disclosure
{8, 10, 11} -> 12 flow
7 -> 13 challenge cap
{8, 11, 12, 13} -> 14 issuance
{6, 8, 9, 14} -> 15 prune/report
{11, 12, 13, 14, 15} -> 16 wiring/architecture -> 17 mutation/full-engine gate
```

## Task 1: Freeze the baseline and name inherited controls

**Estimate:** 1–2 h

**Dependencies:** none

**Files:**
- Modify: `PROJECT.md`
- Modify: this plan only if current commands differ

- [x] Record `git status --short`, HEAD, branch, default Pest result, PHPStan result,
  and the current three-engine suite result before source changes.
- [x] Run the current lockout, strict retry, API surface, timing equalization,
  enrollment contention, challenge, prune, and provider-wiring tests as a named
  baseline. A missing or skipped file is not green.
- [x] Record the current Phase 2 mutation manifest identity. 2.3b will add new
  expressions, so final reconciliation is against a regenerated manifest rather than
  inherited counts.
- [x] Commit only tracking text if it changed.

**Recorded 2026-08-16:** clean `10ad1f1` on `feat/vouch-2-3-flow-http`; default
720 passed / 9 skipped / 2,400 assertions; PHPStan level 9 clean; 109 named-control
tests / 196 assertions on file-backed SQLite with no skips; and 729 tests / 2,419
assertions on each of SQLite 3.53.4, MySQL 8.4.11, and PostgreSQL 16.14. The inherited
manifest is the patched 2026-08-15 1,314-mutation run, keyed by its SHA-256 in
`PROJECT.md`; it is not a substitute for Task 17 regeneration.

**Gate:** default suite and PHPStan remain green before Task 2 begins.

## Task 2: Add throttle binding domains and canonical subjects

**Estimate:** 6–9 h

**Dependencies:** Task 1

**Files:**
- Modify: `composer.json`, `composer.lock`
- Modify: `src/Sessions/BindingDomain.php`
- Modify: `src/Sessions/SessionBinding.php`
- Create: `src/Throttle/IdentifierCanonicalizer.php`
- Create: `src/Throttle/IpCanonicalizer.php`
- Create: `src/Throttle/ThrottleKey.php` (or equivalently narrow value type)
- Test: `tests/Database/ThrottleKeyTest.php`
- Test: `tests/Arch/ThrottleKeyBoundaryTest.php`

- [x] Promote `symfony/string` to an explicit production dependency compatible with
  the supported Laravel/Symfony range. Do not rely on the current transitive package
  or local `ext-intl`.
- [x] Add required, non-defaulted domains: identifier, recovery, issuance, IPv4,
  IPv6 `/64`, IP+identifier tuple, tenant, and global. Preserve byte-identical
  outputs for the existing Session and Attempt domains. Issuance became a distinct
  state sink in Task 7; reusing the identifier HMAC would make the table dimension,
  rather than the derivation type, carry the separation rule.
- [x] Extend HMAC derivation for explicit, unambiguous segments. Tests must distinguish
  absent tenant from empty tenant and separator-looking inputs; local string
  concatenation outside the derivation class is forbidden.
- [x] Canonicalize identifiers with Unicode lowercase plus NFC. Prove composed and
  decomposed forms derive identically, case variants derive identically, and
  provider-specific aliases such as Gmail dots remain distinct.
- [x] Canonicalize IPv4 through binary parsing/round-trip. Canonicalize IPv6 through
  `inet_pton`/`inet_ntop`, zero the host half, and derive one bucket per `/64`.
  Equivalent textual forms and privacy addresses inside one `/64` must match;
  neighboring `/64`s must not.
- [x] Model invalid and null IP separately. Invalid IP fails loudly at the boundary;
  null skips the IP dimension and never derives a shared “unknown” key.
- [x] Prove APP_KEY rotation changes throttle keys and document that it resets counters
  and locks. Prove no raw subject or candidate appears in the derived value.
- [x] Probe removal of the domain, NFC normalization, `/64` mask, absent-tenant marker,
  and NUL/segment separation individually.

**Recorded 2026-08-16:** 47 focused tests / 120 assertions; full suite 739 passed /
9 skipped / 2,476 assertions; PHPStan level 9 and Composer strict validation clean.
`php -n` proves the Symfony polyfill path. Each of the five named probes fails, and
IPv4-mapped IPv6 is additionally pinned to its underlying IPv4 bucket. Task 7 adds
the issuance domain and a typed `ThrottleSubject` around every derived value before
the persistence interface can consume one.

**Focused gate:** throttle-key tests, session-binding tests, API/architecture tests,
PHPStan.

**Commit:** `feat: add canonical throttle subjects`

## Task 3: Extract a restoring bounded-lock primitive

**Estimate:** 10–14 h

**Dependencies:** Task 1

**Files:**
- Create: `src/Support/BoundedLockWait.php`
- Create: `src/Support/LockContention.php` if classification is separated
- Modify: `src/Enrollment/EnrollmentGuard.php`
- Modify: `src/VouchServiceProvider.php`
- Modify: `tests/Concurrency/EnrollmentContentionTest.php`
- Modify: `tests/Database/EnrollmentWaitBoundTest.php`
- Test: `tests/Database/BoundedLockWaitTest.php`
- Test: `tests/Concurrency/BoundedLockWaitContentionTest.php`

- [x] Write direct tests that inspect the bounded value *inside* the primitive's
  critical section and the exact prior value after it exits.
- [x] Cover success, verified contention, unrelated `QueryException`, caller
  exception, and nested scopes. The nested proof is host `H` → throttle `1` →
  enrollment `5` → restore `1` → restore `H`.
- [x] Read and restore `@@SESSION.innodb_lock_wait_timeout`, `PRAGMA busy_timeout`,
  and PostgreSQL `lock_timeout` per invocation. Restoration lives in `finally`; no
  engine-global default is substituted for the captured prior value.
- [x] Preserve the measured classifier exactly: MySQL 1205, PostgreSQL 55P03, SQLite
  5. Unknown drivers and deadlock siblings stay loud until separately measured.
- [x] Move `EnrollmentGuard` to the primitive, remove/rewrite its `KNOWN SIDE EFFECT`
  docblock, and prove enrollment remains fail-closed.
- [x] Split the old combined assertion: primitive tests own set/readback/restore;
  `EnrollmentContentionTest` owns real held-lock liveness and refusal. Keep both.
- [x] Prove the shared throttle wait budget cannot be configured above one second;
  EnrollmentGuard retains its separate configured five-second default.
- [x] Probe deleting the set call, deleting restoration, restoring a default instead
  of the prior value, widening the classifier, and removing EnrollmentGuard's use of
  the primitive.

**Focused gate:** database primitive tests on all three engines plus the complete
enrollment contention suite.

**Recorded 2026-08-16:** 55 focused tests passed on each of file-backed SQLite,
MySQL 8, and PostgreSQL 16 (92/94/94 assertions, no skips); PHPStan level 9 clean.
All five named probes fail. PostgreSQL adds one measured nuance: after a statement
failure aborts a transaction, an explicit restore is itself rejected with `25P02`.
The bound is therefore transaction-local there; normal/nested exits restore
explicitly, while rollback restores an aborted scope without masking its original
query error. Ordinary 128M gate: 748 passed / 10 skipped / 2,502 assertions;
PHPStan level 9 clean.

**Commit:** `fix: restore database lock wait settings`

## Task 4: Amend `RetryPolicy` deliberately

**Estimate:** 4–6 h

**Dependencies:** Task 1

**Files:**
- Modify: `src/Kernel/Screen/RetryPolicy.php`
- Modify: `src/Kernel/Enumeration/ErrorShaper.php`
- Modify: `tests/Kernel/Enumeration/ErrorShaperTest.php`
- Modify: `tests/Kernel/Screen/ScreenSpecTest.php`
- Modify: `tests/Arch/ApiSurfaceTest.php` only if its diagnostics need updating
- Regenerate: `docs/kernel-api-surface.md`
- Modify: `PROJECT.md`

- [x] Append `?DateTimeImmutable $retryAfter = null` as the third constructor
  parameter so existing named and positional calls remain source-compatible.
- [x] Update the docblock: retryAfter is posture-shaped measured backoff; lockedUntil
  remains identifier-lock state only.
- [x] Under strict posture, null attemptsRemaining while preserving measured
  retryAfter for ordinary refusals. The initial Task 4 implementation preserved full
  lock state; Task 11 completed the scope-amendment contract by retaining the lock
  deadline while redacting its counter. Friendly posture keeps permitted fields.
- [x] Prove strict shaping is identical for known/nonexistent outcomes when handed the
  same measured state. The stronger state-progression proof requires the Task 12 store
  and remains explicitly assigned there; a shaper-only test is not substituted for it.
- [x] Run `php bin/kernel-api-surface.php`, review its output, update the snapshot with
  `apply_patch`, and verify a second generator run is byte-identical. Record the
  intentional post-2.3 amendment in PROJECT.
- [x] Mutation-probe each nullable field independently and probe dropping the strict
  attemptsRemaining redaction.

**Focused gate:** all kernel tests, API surface, PHPStan, kernel mutation gate.

**Recorded 2026-08-16:** 132 kernel/API tests / 366 assertions; generated surface
byte-identical on the verification run; PHPStan level 9 clean. Four independent
disclosure probes fail. Kernel mutation gates: 86.96% overall (230 mutations) and
97.54% covered-only (203 mutations), retaining the frozen 80/95 floors. Ordinary
suite: 753 passed / 10 skipped / 2,516 assertions. Actual known/nonexistent counter
progression remains a Task 12 obligation.

**Commit:** `feat: add measured retry deadline to kernel`

## Task 5: Define configuration and fail at boot

**Estimate:** 6–8 h

**Dependencies:** Task 1

**Files:**
- Modify: `config/vouch.php`
- Create: `src/Throttle/ThrottleConfiguration.php`
- Modify: `src/VouchServiceProvider.php`
- Test: `tests/Database/ThrottleConfigurationTest.php`
- Test: `tests/Database/ProviderEffectTest.php`

- [x] Add the adopted defaults: 900-second window; identifier backoff after 5,
  lock after 10, base 2, initial 1 second, cap 60 seconds; 900-second lock default;
  3600-second hard maximum; five challenge attempts; five issuances per identifier
  per 900 seconds; 86400-second scalar retention.
- [x] Apply the same bounded backoff schedule to the recovery domain without granting
  it lock authority. Recovery remains reachable while identifier-locked.
- [x] Add IPv6 `/64` observation threshold 30 and IPv4 distinct-identifier threshold
  300. Shared mode defaults to observe; tenant/global enforcement thresholds default
  null. Shared enforcement requires an explicit seconds-scale backoff bound and never
  silently uses observation values.
- [x] Validate types and relationships at provider boot: positive values,
  `backoff_after < lock_after`, backoff cap ≤ window, lock ≤ 3600, retention ≥ window
  + maximum lock, IPv4 threshold > IPv6 threshold, and complete shared-enforcement
  configuration.
- [x] Empty environment variables must fail loudly rather than become zero through an
  `(int)` cast. Error messages name the exact key and violated relationship.
- [x] Prove defaults by leaving keys unset. Separate tests cover explicit values; a
  helper that passes the default is not evidence the default was read.
- [x] Probe every boundary from both sides and remove one shipped config key to prove
  the provider does not fall back to a duplicate inline default.

**Focused gate:** configuration and provider-effect tests, full default suite,
PHPStan.

**Recorded 2026-08-16:** one validated singleton owns the global schedule; recovery
reuses that schedule but has no configuration surface granting lock authority. The
provider resolves it before routes or migrations, so blank, missing, non-positive, or
relationally-invalid security budgets abort boot with the exact key. The current OTP
and TOTP code spaces and drift window participate in validation: the fixed-window
worst case must remain at or below `10^-4`, rather than allowing two independently
reasonable caps to multiply into an unreviewed guess budget.

The focused contract passed **91 tests / 250 assertions**; the ordinary gate passed
**803 tests / 10 skipped / 2,701 assertions**; and PHPStan level 9 is clean. The
following independent probes fail as intended: change an unset default; widen
`backoff_after < lock_after`; tighten the retention equality boundary; bypass both
guess-budget calculations; bypass IP enforcement validation; delete
`vouch.throttle.window_seconds` from the shipped config; or launch with that
environment variable set to an empty string.

**Commit:** `feat: define throttle configuration`

## Task 6: Add the four persistence tables

**Estimate:** 7–10 h

**Dependencies:** Tasks 1 and 5

**Files:**
- Create: `database/migrations/2026_08_15_000001_create_auth_throttle_counters_table.php`
- Create: `database/migrations/2026_08_15_000002_create_auth_throttle_locks_table.php`
- Create: `database/migrations/2026_08_15_000003_create_auth_throttle_ip_windows_table.php`
- Create: `database/migrations/2026_08_15_000004_create_auth_throttle_tuples_table.php`
- Test: `tests/Database/ThrottleSchemaTest.php`
- Modify: `tests/Database/AmendmentsRollbackTest.php`

- [x] Scalar counters store only domain/dimension, HMAC digest, database-clock window
  start, count, and operational timestamps. Identifier lock rows store digest and
  locked_until separately.
- [x] IP-window parents store family/domain, IP digest, and current window start. Tuple
  markers reference the parent, carry tuple digest plus the exact window generation,
  and enforce one marker per `(parent, generation, tuple)`.
- [x] Choose indexes from actual queries: scalar subject lookup, active lock lookup,
  parent lookup/lock, indexed tuple `COUNT`, and prune deadlines. No raw identifier,
  IP, tenant, user id, or readable debug column exists.
- [x] Avoid enum/check assumptions that compile differently across engines unless the
  compiled DDL is asserted for all three.
- [x] Test all unique/FK/cascade rules, four-table rollback order, digest length, null
  prohibition, and max values. Inspect compiled MySQL/PostgreSQL/SQLite DDL for every
  default the store relies on.
- [x] Prove tuple markers can be pruned without deleting the persistent parent needed
  for the committed-row serialization path.

**Focused gate:** schema and rollback tests on all engines, PHPStan.

**Recorded 2026-08-16:** the four tables are narrow by construction and contain no
raw identifier, IP, tenant, user id, or debug value. Scalar counters and identifier
locks are independent; IP windows are persistent serialization parents; tuple markers
are unique by `(parent, exact generation, tuple)` and may be pruned without removing
that parent. Actual query prefixes own named indexes rather than relying on an
incidental index Laravel might generate.

The focused gate passed **49 tests** on SQLite 3.53.4, MySQL 8.4.11, and PostgreSQL
16.14 (123/127/127 assertions). The test that forbids implicit store defaults caught
that Laravel's ordinary `timestamps()` helper makes operational timestamps nullable;
all four tables now declare them non-null explicitly. Laravel 13's SQLite grammar also
compiles `char(64)` to unconstrained `varchar`, while MySQL/PostgreSQL preserve 64 in
real metadata. Tests therefore pin the `char(64)` migration declaration everywhere,
the actual length where the grammar retains it, and Task 2's producer-side 64-byte
HMAC contract rather than inventing an unmeasured check constraint.

Four destructive probes fail independently: remove scalar uniqueness; remove the
fixed-window generation from tuple identity; remove tuple cascade behavior; or make an
operational timestamp nullable. Ordinary gate: **851 passed / 10 skipped / 2,810
assertions**; PHPStan level 9 clean.

**Commit:** `feat: add authentication throttle schema`

## Task 7: Define the auth-specific store surface

**Estimate:** 5–7 h

**Dependencies:** Tasks 2, 5, and 6

**Files:**
- Create: `src/Contracts/AuthThrottleStore.php`
- Create: `src/Throttle/ThrottleDimension.php`
- Create: `src/Throttle/ThrottleDecision.php`
- Create: `src/Throttle/IdentifierThrottle.php`
- Create: `src/Throttle/SharedThrottle.php`
- Test: `tests/Database/ThrottleContractTest.php`

- [x] Keep the public contract auth-specific. It accepts canonical/HMAC subjects, not
  arbitrary keys and not resolved users.
- [x] Keep identifier results and shared results separate in the type system.
  Identifier results may carry attemptsRemaining and lockedUntil; shared results may
  carry retryAfter only.
- [x] Model observe, permitted, backed-off, and identifier-locked outcomes explicitly.
  Do not use null/boolean combinations whose invalid states callers can construct.
- [x] Separate preflight reads, post-failure identifier recording, post-failure shared
  recording, full-auth reset, challenge failure, and issuance permission. The API must
  make identifier-first commit order implementable and reviewable.
- [x] No method accepts raw identifiers/IPs, returns a digest, or exposes a candidate
  lookup. Canonicalization/key derivation stays outside persistence but inside the one
  throttle service boundary.
- [x] Contract tests provide a recording implementation and prove each operation stays
  distinct without database behavior. Task 12 uses this exact fixture to prove
  `AuthFlow` call choice and order; claiming that proof here would require integrating
  the flow before the store exists or binding a misleading no-op control.

**Focused gate:** contract tests, architecture tests, PHPStan.

**Recorded 2026-08-16:** `ThrottleSubject` combines the closed dimension enum with one
validated lowercase HMAC-SHA256 digest; production construction is architecture-bound
to `ThrottleKey`. The store cannot accept raw strings, resolved users, or candidate
lookup input. Issuance receives its own binding domain rather than reusing the
identifier digest under a different table label.

Identifier results alone may carry attempts remaining and `lockedUntil`; shared
results expose only `retryAfter`, so a shared caller cannot become lock authority by
reading the wrong nullable field. Named factories make permitted, backed-off, locked,
observed, and contention-skipped states explicit. Challenge failures and issuance
permission have separate enums and separate operations. Focused gate: **34 passed /
149 assertions**; PHPStan level 9 clean. Three destructive probes fail independently:
reuse the identifier HMAC domain for issuance, accept malformed/raw subjects, or drop
the measured retry deadline from a backed-off identifier result. The ordinary gate
reports **866 passed / 10 skipped / 2,900 assertions**.

**Commit:** `feat: define authentication throttle contract`

## Task 8: Implement scalar counters and identifier locks

**Estimate:** 10–14 h

**Dependencies:** Tasks 3 and 7

**Files:**
- Create: `src/Throttle/DatabaseAuthThrottleStore.php`
- Test: `tests/Database/ScalarThrottleStoreTest.php`
- Test: `tests/Concurrency/ScalarThrottleContentionTest.php`

- [x] Implement database-clock fixed-window increment/rollover atomically in SQL; no
  PHP read-modify-write. Use `DatabaseTime::deadlineSqlHere()` for all comparisons.
- [x] Derive cumulative exponential backoff from count, window start, and database now;
  store no separate retry deadline. For `c >= A`, offset is
  `sum(i = 0 .. c-A, min(initial * base^i, cap))`, capped at the window deadline.
  Defaults produce offsets 1/3/7/15/31 seconds at counts 5–9; count 10 locks. Assert
  counts 4/5/9/10, already-passed deadlines, and the exact window boundary.
- [x] Write lock state only when the submitted-identifier count crosses 10. Repeated
  requests during backoff/lock do not increment or extend deadlines.
- [x] Enforce 900-second default lock and 3600-second maximum from validated config.
  Expiry on request is sufficient unlock; prune is never enforcement.
- [x] Make unknown and known identifiers byte-for-byte identical at this layer. No
  model lookup exists in the store.
- [x] Full authentication resets only identifier-specific failure state. Recovery grace
  and per-factor satisfaction do not reset.
- [x] Run same-subject and different-subject two-connection races on every engine. The
  resulting count equals committed failures exactly; no test passes by serial execution.
- [x] Probe the atomic increment, rollover predicate, threshold comparisons, lock write,
  no-extension rule, reset boundary, and database clock independently.

**Focused gate:** scalar database tests plus real-engine contention matrix.

**Recorded 2026-08-16:** scalar creation, rollover, and increment stay in database
time and one SQL update. Default identifier states are exact at counts 4/5/9/10;
active deadlines do not move, an expired lock is a sufficient unlock, and reset owns
only the identifier counter/lock. Recovery uses the same cumulative schedule without
acquiring lock authority; tenant/global counters remain live observations under their
default unarmed modes.

The real race matrix found two engine-specific claim paths. SQLite has to issue its
unique insert before any read because its `FOR UPDATE` is inert and a deferred
read-to-write upgrade cannot wait. MySQL has to avoid `INSERT IGNORE` on a committed
row because concurrent duplicate-key shared locks deadlock when both writers upgrade;
MySQL/PostgreSQL go directly to the exclusive row lock there. Both children open
their database connection before the release barrier and are shown blocked behind the
parent's actual write/row locks, so exact count 2 cannot be a sequential fixture.

Focused gate on file-backed SQLite, MySQL 8, and PostgreSQL 16: **21 passed / 60
assertions per engine**. Ordinary gate: **879 passed / 12 skipped / 2,945
assertions**; PHPStan level 9 clean. Six direct destructive probes and the two failed
engine variants cover the update, rollover, threshold, deadline, no-extension, reset,
duplicate-insert, and read-first mechanisms independently.

**Commit:** `feat: persist identifier throttle state`

## Task 9: Implement distinct-subject IP observation

**Estimate:** 12–18 h

**Dependencies:** Tasks 3 and 7

**Files:**
- Modify: `src/Throttle/DatabaseAuthThrottleStore.php`
- Test: `tests/Database/IpThrottleStoreTest.php`
- Test: `tests/Concurrency/IpThrottleContentionTest.php`

- [x] Ensure/lock the IP-window parent, roll an expired generation under the lock,
  create one marker per canonical tuple, and derive the IP count using indexed
  `COUNT`. Do not denormalize via `insertOrIgnore()` affected-row results.
- [x] Count repeated failures for one tuple once and twenty distinct submitted
  identifiers twenty times. Prove IPv4 and IPv6 domains cannot share a bucket.
- [x] Keep observation live at 30/300 while default enforcement is disabled. An
  observation threshold crossing changes no response.
- [x] Bound parent acquisition to one second using Task 3's primitive. On verified
  contention, roll back shared state and return a skipped/advisory result; unrelated
  database errors propagate.
- [x] Preserve tuple markers through successful authentication. Their one-window
  lifetime is independent of identifier reset.
- [x] Add exact-boundary database-clock tests: old markers stop counting at rollover,
  one new generation wins, and a prune cannot remove a marker from the active window.
- [x] Probe removing `lockForUpdate`, widening wait, using raw failure count, deleting
  the unique marker rule, counting old generations, and treating contention as refusal.

**Focused gate:** IP store tests on each engine.

**Recorded 2026-08-16:** the store counts unique tuple markers for the exact parent
generation; it never infers distinctness from affected-row values or a denormalized
counter. Parent rollover retains old evidence while excluding it from the live count,
and identifier reset does not touch markers. IPv4 and IPv6 stay separate by typed
dimension.

Observe mode remains inert at 30/300. Opt-in enforcement anchors its measured deadline
to the threshold-crossing marker's database `created_at`, capped by the window
deadline. While active, no marker is admitted and no deadline can extend; a repeated
tuple cannot create breadth backoff at all. Verified one-second contention returns
`Skipped` and writes nothing, while a missing tuple table propagates as a schema fault.

Focused behavior plus held-parent gate on file-backed SQLite, MySQL 8, and PostgreSQL
16: **11 passed / 33 assertions per engine**. Ordinary gate: **888 passed / 14 skipped
/ 2,971 assertions**; PHPStan level 9 clean. The last destructive-probe item remains
open deliberately: Task 10's simultaneous committed-parent cells are the only
non-vacuous place to kill `lockForUpdate` on PostgreSQL.

**Commit:** `feat: observe distinct subjects per IP`

## Task 10: Prove the six contention cells and safe degradation

**Estimate:** 12–18 h plus engine runtime

**Dependencies:** Tasks 8 and 9

**Files:**
- Modify: `tests/Concurrency/IpThrottleContentionTest.php`
- Create: `tests/Concurrency/ThrottleFailOpenTest.php`
- Modify: `.github/workflows/ci.yml` only if the existing full matrix does not select
  every new test

- [x] Cross `{same tuple, distinct tuple}` with `{parent absent, parent committed and
  active, parent committed and expired}` on file-backed SQLite, MySQL 8, PostgreSQL 16.
  These are six cells per engine, not one parameterized assertion whose fixture always
  creates the row the same way.
- [x] Hold the parent lock from one real connection and execute the store from another.
  Prove bounded return, verified contention classification, no shared write, and prior
  connection-setting restoration.
- [x] End-to-end, commit identifier state first, then force shared timeout. Assert the
  identifier reaches lock at 10 while tuple/IP state remains absent and no shared
  lockedUntil/retry is fabricated.
- [x] Kill `lockForUpdate` and prove PostgreSQL's committed-parent cases fail while
  first-parent cases may continue to pass. Record the engine asymmetry rather than
  weakening the expectation to the MySQL result.
- [x] Force a missing table and bad column and prove neither is swallowed as advisory
  contention.
- [x] Verify non-vacuity: both processes cross a ready/release barrier after opening
  their connections, every test makes assertions, and `set -o pipefail` preserves
  child failures in any shell harness.

**Gate:** all six cells and fail-open proof on all three engines. Task 12 may not begin
against an unproven store.

**Recorded 2026-08-16:** all six cells pass on file-backed SQLite, MySQL 8,
and PostgreSQL 16: same/distinct tuple crossed with absent, committed-active,
and committed-expired parent. Both child processes open their connections before
the ready/release barrier; committed parents are held by a third connection and
neither child returns before release.

The matrix found a real MySQL snapshot defect in the first implementation. Reading
parent existence inside an InnoDB `REPEATABLE READ` transaction fixed the snapshot
before `FOR UPDATE`; the waiting writer acquired the lock after the first committed,
but still counted the old snapshot and admitted both distinct subjects. Existence
hints now come from autocommit before the transaction, while all decisions remain
under the locked read. Removing only the parent `lockForUpdate()` makes PostgreSQL's
distinct committed-parent case return two `Permitted` decisions instead of one
`BackedOff`; the absent-parent insert path continues to serialize independently.

Verified contention is advisory-only: identifier count and lock commit first, the
subsequent IP timeout returns `Skipped`, and no tuple is written. Missing table and
renamed-column faults propagate as `QueryException` rather than being misclassified
as contention. Focused gate: **10 passed / 59 assertions per engine**.

**Commit:** `test: prove throttle serialization across engines`

## Task 11: Carry measured retry state through the disclosure authority

**Estimate:** 6–9 h

**Dependencies:** Tasks 4 and 7

**Files:**
- Modify: `src/Flow/ScreenBuilder.php`
- Modify: `src/Http/FlowResultSerializer.php`
- Modify: `tests/Flow/ScreenBuilderTest.php`
- Modify: `tests/Http/PayloadContractTest.php`
- Modify: `tests/Http/StrictPostureRetryTest.php`
- Modify: `tests/Kernel/Enumeration/ErrorShaperTest.php`

- [x] Replace hardcoded retry null with serialization of
  `attemptsRemaining`, `lockedUntil`, and `retryAfter`, preserving the existing `retry`
  envelope key and explicit null when no policy exists.
- [x] Let ScreenBuilder construct measured ordinary refusal and identifier-lock
  policies, then pass them through ErrorShaper. Delete the 2.3 lockout prohibition only
  after its precondition is satisfied by tests.
- [x] Strict posture: known/nonexistent identifiers receive identical retryAfter and
  lockedUntil schedules; attemptsRemaining is null. Friendly posture may show permitted
  attempts remaining. Shared state can populate retryAfter only.
- [x] `Outcome::Locked` comes only from identifier state and carries lockedUntil under
  every posture. No shared path may reuse it.
- [x] Rewrite the current retry-null tests to assert the new behavior from both sides.
  Keep cases proving null when nothing was measured.
- [x] Probe hardcoding retry null, leaking attemptsRemaining under strict, dropping
  retryAfter, and mapping shared backoff to lockedUntil.

**Focused gate:** kernel shaping, ScreenBuilder, wire-contract, and strict-posture HTTP
tests.

**Recorded 2026-08-16:** `ScreenBuilder` accepts typed `IdentifierThrottle` or
`SharedThrottle` state and is the only flow/HTTP component that constructs
`RetryPolicy`. Identifier state may supply attempts remaining, ordinary retry, or a
lock deadline. Shared state can supply only an active retry deadline; presenting a
shared result as `Outcome::Locked` throws before shaping. `FlowResultSerializer`
preserves the existing `retry` key and emits the complete ordered shape
`attemptsRemaining`, `lockedUntil`, `retryAfter`, with database-derived deadlines in
ATOM form and explicit null when nothing was measured.

Strict posture redacts attempts remaining for ordinary backoff and lockout while
preserving the actionable measured deadline. Friendly posture preserves permitted
counter state. Four destructive probes fail: hardcoded retry null, omitted
`retryAfter`, leaked strict counter state, and shared backoff mapped to
`lockedUntil`. The last probe initially stayed green because strict shaping was a
compensating control; adding a friendly-posture assertion made the builder's primary
mapping independently observable. Focused gate: **48 passed / 114 assertions**.
Ordinary gate: **893 passed / 22 skipped / 2,991 assertions**; PHPStan level 9 clean.

**Commit:** `feat: disclose measured throttle retry state`

## Task 12: Integrate throttling into `AuthFlow`

**Estimate:** 14–20 h

**Dependencies:** Tasks 8, 10, and 11

**Files:**
- Modify: `src/Flow/AuthFlow.php`
- Modify: `src/VouchServiceProvider.php`
- Test: `tests/Flow/AuthThrottleFlowTest.php`
- Modify: `tests/Flow/TimingEqualizationTest.php`
- Modify: `tests/Http/StrictPostureRetryTest.php`

- [x] Preflight identifier lock/backoff and shared backoff before expensive credential
  verification. Active refusal does not increment or extend any deadline.
- [x] On every credential failure, commit identifier state first. Then attempt IP tuple,
  tenant, and global observations in separate advisory transactions.
- [x] Couple both existing `VerificationEqualizer::equalize()` sites to the same
  identifier increment. Removing either equalization or either increment must fail a
  distinct test.
- [x] Count ordinary mismatch, malformed/binding/no-credential paths according to the
  one event table. Do not count successful-factor CAS loss as credential failure.
- [x] Use the submitted identifier stored on the attempt, never `user_id`. Known and
  nonexistent attempts must hit identical keys/schedules after canonicalization.
- [x] Recovery bypasses identifier lock but uses its own digest/counter and bounded
  backoff. It can never write identifier lock state or reset login failures.
- [x] Reset identifier state only after the final Authenticated transition succeeds.
  First-factor satisfaction and RecoveryGraceStarted do not reset.
- [x] Prove identifier-first crash direction with a selective store double and real DB
  integration: authoritative count may exist without shared evidence; the reverse is
  not required and no count-reconciliation assertion is introduced.
- [x] Probe resolved-user keying, shared-first order, reset after one factor, increment
  during active backoff, increment on CAS loss, and swallowed shared schema errors.

**Focused gate:** flow, timing, strict-posture, transition-failure, and full HTTP tests.

**Recorded 2026-08-16:** `AuthFlow` derives state exclusively from the submitted
identifier persisted on the attempt. Known and nonexistent identifiers traverse the
same preflight and recording operations; a test with two identifiers owned by the
same user kills resolved-user keying. The host tenant is persisted when the attempt
is created, null IP skips that dimension rather than entering a global unknown
bucket, and recovery uses its separate scalar subject while bypassing and preserving
login lock state.

Every verification failure commits identifier/recovery state before IP, tenant, and
global work. A decorator delegates the authoritative write to the real database store
and fails only the following IP call; the failure propagates while the identifier
count remains committed. Store-level malformed-table/column propagation remains
separately proven by Task 10. The first attempted fixture used DDL to break the tuple
table; MySQL implicitly committed the test transaction and failed on a missing
savepoint, so it was rejected as non-discriminating rather than normalized into a
cross-engine assertion.

Preflight refusals perform no verification or increment. Full authentication resets
identifier state only after the final CAS succeeds; a first factor, recovery grace,
and a lost satisfy CAS do not reset or increment it. Destructive probes kill
resolved-user keying, reset-after-first-factor, active-backoff fallthrough, and the
ordering/reset/CAS assertions cover shared-first, swallowed advisory failure, and
CAS-loss charging. Focused gate: **66 passed / 170 assertions**. The 13-test flow
integration file passes with **39 assertions** on SQLite, MySQL 8, and PostgreSQL 16;
ordinary gate: **906 passed / 22 skipped / 3,035 assertions**; PHPStan level 9 clean.

**Commit:** `feat: throttle authentication failures`

## Task 13: Cap and invalidate challenge attempts

**Estimate:** 8–12 h

**Dependencies:** Task 7; may run in parallel with Tasks 8–12

**Files:**
- Add a narrow challenge-attempt operation to the store contract/implementation
- Modify: `src/Factors/Drivers/OtpFactor.php`
- Modify: `src/Models/AuthChallenge.php`
- Modify: `src/Attempts/DatabaseAttemptStore.php` if it remains the single challenge
  writer
- Test: `tests/Factors/OtpChallengeAttemptsTest.php`
- Test: `tests/Concurrency/ChallengeAttemptContentionTest.php`
- Modify: `docs/superpowers/mutation/2026-08-15-matrix-rulings.md`

- [x] Keep one database writer for challenge state. Do not let the driver and two stores
  independently write `attempts`/`consumed_at`.
- [x] Allow at most five guesses: after the fifth failed comparison, invalidate the
  challenge. A correct fifth guess may succeed; a sixth request cannot verify.
- [x] Increment/invalidate atomically under concurrent wrong/correct submissions. A
  challenge cap never writes identifier lock state.
- [x] Keep expired, consumed, wrong-attempt, and binding-mismatch outcomes distinct
  internally while preserving posture-shaped output.
- [x] Prove the cast and integer boundary on all engines, then re-rule
  `AuthChallenge:39` by expression. The cast itself may remain equivalent on current
  PDO drivers; the SQL update—not the cast—is the security mechanism.
- [x] Probe off-by-one in both directions, non-atomic PHP increment, failure to consume,
  and resetting attempts on resend.

**Implemented 2026-08-16.** The one writer performs increment and terminal
invalidation in one conditional SQL update, then reads the result before releasing
the row. The cross-engine gate caught MySQL's left-to-right `SET` evaluation: placing
the increment before the terminal `CASE` invalidated at four on MySQL while SQLite
and PostgreSQL correctly invalidated at five. The terminal assignment now precedes
the increment so every engine evaluates the old count.

Two wrong children released against one parent-held row produce exactly Remaining +
Invalidated. A simultaneous fifth wrong guess and correct consume are mutually
exclusive: either the wrong guess invalidates and the transition refuses, or the
transition consumes and the wrong writer observes Consumed. Both children are proven
blocked before the parent releases the row. A caller-supplied challenge model is
re-read before verification, so a stale pre-consumption object cannot claim success
and defer the refusal to the later mutation.

Focused gate: **9 passed / 67 assertions** on each of file-backed SQLite, MySQL 8,
and PostgreSQL 16. The probes independently kill early and late off-by-one, missing
terminal consumption, PHP read-modify-write collapse, resend reset, and removal of
the authoritative challenge re-read. Ordinary gate: **913 passed / 24 skipped /
3,091 assertions**; PHPStan level 9 clean.

**Focused gate:** OTP factor/store tests and real-engine concurrent challenge tests.

**Commit:** `feat: cap OTP challenge attempts`

## Task 14: Repair production OTP issuance, cap it, and establish the 2.3c seam

**Estimate:** 16–24 h

**Dependencies:** Tasks 8, 11, 12, and 13

**Design gate:** Resolved in
[`2026-08-15-vouch-phase-2-3b-scope-amendment.md`](../specs/2026-08-15-vouch-phase-2-3b-scope-amendment.md)
and the Task 14 delivery-lifecycle record in `PROJECT.md` before source work.

**Files:**
- Create: `src/Factors/ChallengeIssuer.php`
- Create: `src/Factors/ChallengeIssuanceIntent.php`
- Modify: `src/Flow/AuthFlow.php`
- Modify: `src/Factors/ChallengeRequest.php` only if the existing shape cannot carry
  the selected server-owned target safely
- Modify: `src/Factors/Drivers/OtpFactor.php`
- Create: an `auth_challenge_outbox` migration/model selected by the amendment
- Create/modify: durable worker/queue files selected by the amendment
- Test: `tests/Flow/OtpIssuanceFlowTest.php`
- Modify: `tests/Factors/OtpFactorTest.php`
- Modify: `tests/Http/AuthEndpointTest.php`
- Modify: `tests/Arch/ThrottleBoundaryTest.php`

- [ ] Begin with a test proving current AuthFlow issues no actual challenge. Keep it as
  the negative control and record the Phase 2.3 correction; a volume counter increment
  alone must not satisfy the task.
- [ ] Prove the second negative control: current `OtpFactor::challenge()` commits a row
  before synchronous delivery; a throwing transport leaves that row present. Use a
  barrier-controlled transport: assert the request cannot complete before release,
  then throw and assert the committed row remains. Do not substitute an elapsed-time
  threshold for either property.

**Recorded implementation deviation:** the two historical negative-control tests above
were not retained. The pre-fix absence is instead discriminated by the public
email/SMS endpoint test failing against the pre-fix source, while atomic rollback and
request-path isolation are probed directly against the implemented boundary. This is a
process-artifact gap, not an untested production property; the boxes remain unchecked
rather than retroactively claiming otherwise.

- [x] Before implementation, amend the design to settle challenge verifiability/state
  meanings, durable worker dispatch/recovery, provider
  retry/permanent-failure behavior, resend coalescing, and unconfigured-host behavior.
  Request-path isolation and an encrypted TTL-bound outbox are requirements, not
  options. A database transaction around a network call may not be described as atomic.
- [x] Introduce `ChallengeIssuer` as the sole owner of production challenge issuance.
  Construct a typed, immutable, target-free issuance-attempt intent from submitted
  identifier, action, and the factor id carried by posture-safe flow state before user
  or credential resolution.
- [x] Atomically charge/permit issuance volume before resolving a real target or decoy.
  Known and nonexistent identifiers, on initial issue and explicit resend, must reach
  the cap on the same request. Removing the charge from the no-target branch must fail.
- [x] After volume permission, resolve the server-owned target or decoy without
  choosing silently among credentials. Only then construct any target-bearing delivery
  intent.
- [x] Make the future 2.3c insertion point structural: volume permission first, then
  one named delivery-economics boundary, then the factor call. Ship no fake/no-op
  economics binding in 2.3b; 2.3c adds its required contract at that exact boundary.
  Record the inherited 2.3c test obligation—an economics refusal reaches no factor
  and never re-counts volume—without pretending an absent contract executed in 2.3b.
  The future real-target-only economics work inherits the same request-path isolation.
- [x] Before any driver call, charge one issuance event for identify+first challenge.
  Explicit resend or factor switch charges one more. Screen construction alone does not.
- [x] Enforce five issuances per submitted identifier per 900 seconds before delivery.
  Here “issuance” means an admitted issuance-attempt event, not provider success. 2.3c
  may later refuse/account for economics only after this permission and never rewrites
  or recounts it.
- [x] Invoke the selected challenge implementation only through the delivery lifecycle
  chosen by the amendment, with captured IP/user-agent and no synchronous real-target
  latency on the observable request path. Password/TOTP/recovery return null and incur
  no delivery.
- [x] Create the challenge and outbox atomically in the database, then perform no
  provider I/O before the response. Reject the Laravel `sync` queue driver or any
  equivalent inline executor. Real and decoy paths must perform the same request-side
  durable work shape; the decoy worker path contacts no provider.
- [x] Encrypt the exact issued code and target/message metadata in the outbox. Store
  only its opaque id in queued jobs. Assert raw database, model array/JSON, serialized
  queue payload, failed-job record, and representative logs contain no plaintext code
  or target.
- [x] Retry by reloading and decrypting the same outbox payload; never re-invoke the
  factor/code generator. Prove two delivery attempts carry the same code and still
  match the single `auth_challenges.code_hash`.
- [x] Set outbox expiry to the challenge's database-clock `expires_at`—120 seconds by
  default. Workers refuse expired payloads, retries cannot extend it, and cleanup does
  not inherit throttle retention. Encryption failure has no plaintext fallback.
- [x] Model redacted `pending`, `delivered`, and `undeliverable` states. Provider
  acceptance clears encrypted payload immediately and marks delivered. Permanent
  failure or expiry clears it and records undeliverable without retaining target
  or credential data.
- [x] Treat a missing opaque outbox id as idempotent success with no retry. For a
  present expired row, atomically clear payload, mark undeliverable, and return
  success. Prove a backlog beyond 120 seconds produces neither failed-job rows nor a
  retry loop.
- [x] Preserve the driver's no-silent-target rule. If multiple active delivery targets
  cannot be represented safely by the current ScreenSpec/request shape, stop this task
  and write the narrow design amendment; do not choose the first target, send to all,
  echo a database id, or let ambiguity become a public 500.
- [x] Implement the parent spec's strict unknown-identifier behavior: a decoy challenge
  can never validate and sends nothing, while status/body and the documented response
  time posture remain indistinguishable. If the current challenge invariant cannot
  represent that row, amend it explicitly with tests rather than bypassing
  `GuardsChallengeTarget`.
- [x] Prove OTP budget multiplication: five live issuances × five attempts, with the
  fixed-boundary maximum still ≤ `10^-4` for six digits.
- [x] Prove delivery is never attempted after volume refusal and first issuance is not
  double-charged by identify plus FactorPending.
- [x] Prove provider retry of one accepted issuance does not charge authentication
  volume again. Prove any refund/skip keyed to target resolution or delivery outcome is
  impossible; outage mitigation belongs to retry/coalescing semantics instead.
- [x] Drive both `email_otp` and `sms_otp` through the public endpoint with a recording
  transport. For each, prove one challenge row is stored for the selected credential,
  one code is delivered to the correct verified identifier, and that code advances the
  same flow to authentication. The test must fail against the pre-fix source.
- [x] Add architecture tests forbidding direct `Factor::challenge()` calls outside
  `ChallengeIssuer` and direct `OtpDelivery` calls outside the outbox worker. Keep the
  future economics edit localized to the issuer rather than spread across AuthFlow.
- [x] Probe removing the permission check, charging screen construction, sending a
  decoy, choosing an ambiguous target, bypassing the issuer, and letting 2.3c-style
  economics leak into the volume owner. Probe target-dependent charge/refund and a
  synchronous transport path separately. Order discrimination for the required
  economics contract belongs to 2.3c when that contract exists.

**Focused gate:** issuance flow, endpoint, OTP driver, strict posture, and budget tests.

**Commit:** `fix: issue and cap authentication challenges`

## Task 15: Prune safely and report aggregates only

**Estimate:** 7–10 h

**Dependencies:** Tasks 6, 8, 9, and 14

**Files:**
- Modify: `src/Console/VouchPruneCommand.php`
- Create: `src/Console/CommandExit.php`
- Create: `src/Console/PruneResult.php`
- Create: `src/Console/VouchPruneSchedule.php`
- Create: `src/Console/VouchThrottleReportCommand.php`
- Create: `src/Throttle/ThrottleReporter.php`
- Modify: `src/Support/DatabaseTime.php`
- Modify: `src/VouchServiceProvider.php`
- Create: `docs/operations.md`
- Modify: `tests/Database/PruneCommandTest.php`
- Test: `tests/Database/ThrottleReportCommandTest.php`
- Test: `tests/Database/VouchPruneScheduleTest.php`
- Modify: `tests/Database/ContainerWiringTest.php`
- Modify: `tests/Database/ProviderEffectTest.php`
- Modify: `tests/Factors/OtpFactorTest.php`

- [x] Prune scalar counters/expired locks only beyond the 86400-second retention floor.
  Enforcement continues to use request-time database predicates; prune never unlocks
  an active subject.
- [x] Prune tuple markers as soon as their own database-clock window completes. Do not
  inherit scalar retention and never prune persistent enrollment-lock rows.
- [x] Prune expired challenge-outbox payloads at their own `expires_at`. Prove the
  credential is unusable at the exact challenge deadline (120 seconds with the current
  default), ciphertext is gone by the next scheduled sweep, and no scalar/throttle
  retention setting can extend either boundary.
- [x] Classify outbox rows before deletion. Report delivered-expired and
  expired-undelivered separately, with every expired row not marked delivered in the
  latter class; warn with the aggregate undelivered count and return status `2` when
  it is positive. Reserve `0` for successful pruning with no undelivered finding and
  `1` for failure of the prune operation itself. A sweep that silently deletes both
  classes or overloads generic non-zero failure fails.
- [x] Prove all three exit meanings independently. Under `2`, assert expired attempts,
  sessions, and outbox rows were actually deleted and exact counts were emitted; under
  `1`, induce a prune failure and prove it cannot masquerade as a worker-health alert.
  Document that monitoring routes `2` to delivery-worker health rather than declaring
  the maintenance command broken.
- [x] Document and test the Laravel scheduler adapter. Direct
  `Schedule::command('vouch:prune')->onFailure(...)` is forbidden because the scheduler
  collapses statuses `1` and `2` into task failure. The supported scheduled callback
  invokes `Artisan::call()`, alerts and completes normally for `2`, completes normally
  for `0`, and throws for `1` or an unknown status. Prove all four branches; a callback
  that merely uses `onFailure()` fails the contract.
- [x] Register and document a cleanup cadence of at most one minute. Prove delivery is
  forbidden at the exact database deadline and physical ciphertext retention is
  bounded by TTL plus one sweep interval. Name the host scheduler/worker requirement;
  enqueue success is not worker-health evidence.
- [x] Extend prune output with exact counts for each security-record category. A silent
  deletion is not an operator record.
- [x] Add `vouch:throttle:report` with human and `--json` output containing only
  dimension, active bucket totals, histogram/distribution bands, and threshold-crossing
  counts, plus aggregate current pending, overdue, delivered, and undeliverable
  outbox health. It does not claim historical delivery telemetry after prune removes a
  row; prune output/exit carries that event.
- [x] The command and underlying contract accept no identifier, IP, tenant, digest,
  generic subject, or arbitrary where/filter input. They emit no per-bucket row.
- [x] Test candidate-lookup absence structurally and behaviorally. Adding `--ip` or
  `--identifier` and deriving a candidate digest must fail the control.
- [x] Prove report totals from known fixtures without asserting on any particular
  digest; prove prune changes expired aggregates and leaves active ones.

**Focused gate:** prune/report/provider tests on all engines.

**Commit:** `feat: report and prune throttle state`

## Task 16: Wire the package and replace temporary architecture bans

**Estimate:** 6–9 h

**Dependencies:** Tasks 11–15

**Files:**
- Modify: `src/VouchServiceProvider.php`
- Rewrite: `tests/Arch/LockoutBoundaryTest.php`
- Modify: `tests/Arch/ThrottleBoundaryTest.php`
- Modify: `tests/Database/ContainerWiringTest.php`
- Modify: `tests/Database/ProviderEffectTest.php`
- Modify: `tests/Http/AuthEndpointTest.php`
- Modify: `PROJECT.md`

- [x] Bind every new service explicitly and assert the complete set, not three examples
  under a test named “all”. Provider boot/config paths must be observable by effect.
- [x] Replace the old blanket lockout ban with scans proving exactly one identifier-lock
  writer and zero populated lockedUntil constructions from shared dimensions. Match
  fully-qualified and imported names; keep a non-empty file-count guard.
- [x] Forbid `Request::ip()`/`->ip()` and forwarding-header reads outside
  `AuthController`. Prove FlowRequest is the only downstream IP source.
- [x] Forbid raw subjects in throttle migrations/models/log/report code and direct HMAC
  derivation outside the key service. Scan source and config, not only one namespace.
- [x] Assert retry remains null when no state was measured and populated only through
  ErrorShaper when it was.
- [x] Update public docs: APP_KEY rotation resets throttles; TrustProxies owns IP trust;
  shared dimensions default observe; admin unlock waits for audited 2.4; tenant/global
  enforcement is opt-in; report is aggregate-only.
- [x] Probe each architecture scan with imported and fully-qualified violating forms.

**Focused gate:** all architecture, provider, endpoint, and documentation contract
tests; PHPStan.

**Commit:** `feat: enforce throttle architecture boundaries`

## Task 17: Regenerate mutation evidence and run the completion matrix

**Estimate:** 10–16 h engineering plus mutation/matrix runtime

**Dependencies:** all tasks

**Files:**
- Modify/create mutation reconciliation artifacts under `docs/superpowers/mutation/`
- Modify: `PROJECT.md`
- Modify: this plan's checkboxes/status

- [ ] Run Pint, default Pest, PHPStan level 9, kernel mutation gates, and the patched
  full Phase 2 mutation run. Verify zero fatal, zero `No tests found`, mutations/files
  matching RUN lines, zero unintended scope, and source-to-RUN reconciliation.
- [ ] Regenerate the survivor manifest. Join by `(file, mutator, expression)`, never by
  filename, line, ID, or prior count. Rule every new survivor/timeout/uncovered row with
  explicit correspondence.
- [ ] Re-rule `AuthChallenge:39` and every expression whose premise changed: retry
  fields, EnrollmentGuard wait handling, AuthFlow equalizer branches, challenge state,
  provider bindings, and pruning/reporting.
- [ ] Run the **full suite** on file-backed SQLite, MySQL 8, and PostgreSQL 16. Record
  engine versions, assertion counts, contention cell counts, and skips. A partial
  directory run is diagnostic only.
- [ ] Run exact negative probes: remove lockForUpdate; remove identifier increment from
  each equalizer path; key by resolved user; map shared timeout to refusal; omit
  challenge invalidation; bypass issuance cap; add subject lookup to report; omit
  connection restoration.
- [ ] Confirm the ordinary suite still runs under its pinned 128M memory posture and the
  mutation-only memory scope remains isolated.
- [ ] Do not restore Phase 2.3's unqualified “Complete” label until public-endpoint
  tests prove both email and SMS OTP issue, deliver, persist, verify, and authenticate.
  Passing throttle tests without that proof leaves the post-certification defect open.
- [ ] Update PROJECT with final commits, test counts, engine evidence, mutation
  reconciliation, remaining residual risks, and merge status. The branch owner's merge
  decision remains separate.

**Completion gate:** no unresolved mutation row; default suite/PHPStan clean; all three
engines green; all discriminating probes fail as intended; working tree clean.

**Commit:** `docs: certify phase 2.3b authentication throttling`

## Commit sequence

Natural boundaries, in dependency order:

1. `feat: add canonical throttle subjects`
2. `fix: restore database lock wait settings`
3. `feat: add measured retry deadline to kernel`
4. `feat: define throttle configuration`
5. `feat: add authentication throttle schema`
6. `feat: define authentication throttle contract`
7. `feat: persist identifier throttle state`
8. `feat: observe distinct subjects per IP`
9. `test: prove throttle serialization across engines`
10. `feat: disclose measured throttle retry state`
11. `feat: throttle authentication failures`
12. `feat: cap OTP challenge attempts`
13. `fix: issue and cap authentication challenges`
14. `feat: report and prune throttle state`
15. `feat: enforce throttle architecture boundaries`
16. `docs: certify phase 2.3b authentication throttling`

Parallel leaf work may change commit chronology, but no commit combines unrelated
leaves merely because they were developed concurrently. Every commit is gated on its
focused tests and PHPStan before the next dependent task begins.
