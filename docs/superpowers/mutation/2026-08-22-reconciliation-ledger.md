# Mutation reconciliation ledger — 2.3c/2.3d baseline

This ledger is pinned to **`66ac67d`**. Every measurement must verify
`git rev-parse HEAD` immediately before starting. The patched
`pest-plugin-mutate` install and the file-backed, `TEST_TOKEN`-scoped SQLite
bootstrap are part of the evidence tuple.

The smoke run provisionally reported **3,155 mutations across 91 files**. The
authoritative mutant-bearing-file count remains **provisional** until it is
recomputed as the sum of the non-compact `RUN` lists from all seven chunks.
The repository contains 162 PHP source files; files
with no generated mutations remain in the inventory below so that a directory
cannot be mistaken for a complete mutant scope. The compact parallel smoke
run is not a ruling artifact: it credited 53 timeouts and suppressed the
`RUN` file list. It is retained only as a harness smoke result.

## Matrix provenance

The three-engine coverage union is blocked until the databases are running.
Use and record this single port choice for the entire reconciliation:

| engine | target |
|---|---|
| file-backed SQLite | `VOUCH_SQLITE_PATH` scoped by `TEST_TOKEN` |
| MySQL 8 | `127.0.0.1:13306` |
| PostgreSQL 16 | `127.0.0.1:15432` |

There is no repository compose file; the matrix host setup must record image
versions, container IDs, and these ports alongside the SHA. Do not substitute
the older port pairs recorded in historical `PROJECT.md` entries.

For each engine, retain only the set of `(file, line)` pairs with a nonzero
Clover execution count. Union the three sets once. A row is `engine-gated` when
its line is absent from SQLite but present in MySQL or PostgreSQL; a line absent
from all three remains unroutable or a genuine gap according to the other
dispositions. Validate the method first against
`DatabaseAuthThrottleStore.php:415–419`.

### Throttle union completed

All three full-suite maps were generated in one sitting at the source-equivalent
state guarded against `66ac67d`:

| engine | result | artifact SHA-256 | container |
|---|---|---|---|
| SQLite | 1,161 passed / 4,092 assertions / 32.15s | `3fdb26087a79ef6d6227ad3ec7879fce1843d3158276bf8c9c4cc1cf715b8daa` | file-backed `/tmp/vouch-union.sqlite` |
| MySQL 8 | 1,161 passed / 4,094 assertions / 77.72s | `da88f26cbe1213c08d7885266940132ceff4c5432a06b5187acfe6671b62d3c2` | `vouch-matrix-mysql`, `618ea48acc9d…`, port `13306` |
| PostgreSQL 16 | 1,161 passed / 4,096 assertions / 71.69s | `4c70761f6f7c808a542e59fe820679540e43bb36547ea9ffce87e5f96268eb9a` | `vouch-matrix-pg`, `62ad6e01115a…`, port `15432` |

The committed classifier ran once with SQLite as `--map` and both other maps as
`--union`. It emitted the reusable executed-line set
(`0000242fc84ba3be5884a0dfe136a0e7780cdcd7ef0a953d0fcc6f731e1faee1`) and
classified the 126 Throttle rows as 86 executed-and-survived (3 contested
against the coverage map), 27 never-executed, 10 engine-gated, and 3
instrument-unroutable. Coverage informs `UNCOVERED` rows only; plugin-reported
`UNTESTED` rows remain survivors even when their signature line is absent from
the map. Timeout rows receive a separate unresolved disposition. The union rescued
the reference `DatabaseAuthThrottleStore.php:415–419` branch. In
`ThrottleConfiguration`, the 22 uncovered rows resolve to 19 never-executed,
3 instrument-unroutable, and 25 executed-and-survived rows—mostly genuine
validation gaps, as predicted.
The corrected classifier artifact is committed at
`artifacts/2026-08-22-throttle-classification.json` (SHA-256
`fc383dcfe5e2c8c27d37bbc965e61de8c24ee309bbfe723e6f606a75264f016b`); the
emitted line set is committed as `.txt`, not `.json`, because the tool writes
plain `path:line` records.

The emitted union is repo-wide, not Throttle-scoped: it contains 3,829
executed lines across 126 files and is reusable by every pending chunk through
`--lines=artifacts/2026-08-22-throttle-union-lines.txt`. It is valid only while
the guarded source-equivalence paths remain unchanged from `66ac67d`; any
change under `src/`, `tests/`, `composer.*`, `phpunit.xml`, `pest.php`,
`config/`, or `database/` invalidates the set and requires all three engine
maps to be regenerated together.

Three repo-wide predictions are now confirmed by the union: the lines for
`VouchDoctorCommand.php:84`, `OtpOutboxDelivery.php:129`, and `AuthFlow.php:717`
are absent from all three maps. Their future `UNCOVERED` rows are therefore
`never-executed`, not engine-gated.

### Post-test confirmation coverage union

The Tier 1/2 test additions are pinned at
`3f3b984b9acddb2b5fe1dc7a7621202b8eb7c89f`. The prior union remains historical
evidence for the `66ac67d` disposition pass and must not be overwritten. A
fresh three-engine coverage sitting was run at this SHA:

| engine | result | Clover SHA-256 |
|---|---|---|
| file-backed SQLite | 1,171 passed / 4,108 assertions / 31.90s | `f2ebca6f48aa8857f184504fab22f1538fea4331f04bd51b8482e0ba13f2ec94` |
| MySQL 8 | 1,171 passed / 4,110 assertions / 68.55s | `140a8413e1b3cb15756b0bd56d8fa36950a3ccebf8db5263593d0a3239c494c7` |
| PostgreSQL 16 | 1,171 passed / 4,112 assertions / 64.15s | `a4cf55e775d8f73de19736a2c3d0b2a2d230c92cbcc7a03a91c60f6e7d2ad54b` |

This is confirmation evidence only until the affected mutation chunks are
rerun at this SHA. The old line set remains the classifier input for the
historical artifacts; the new union must be emitted alongside the new logs
before post-test dispositions are claimed.

### Post-flake-fix routing check

The CAPTCHA discriminator timing fix is committed at `62e51eb`; `77b257a` adds
ledger documentation only, so the guarded source-and-test tree is
source-equivalent to `62e51eb`. The three full-suite maps were regenerated at
that state:

| engine | result | Clover SHA-256 |
|---|---|---|
| file-backed SQLite | 1,171 passed / 4,108 assertions / 32.20s | `bda3beec044f7099e0b442131868f02e84b3e912498b279df34856554157f820` |
| MySQL 8 | 1,171 passed / 4,110 assertions / 67.69s | `54990cb0a19151d5770fc7a5251cd1b4bd539b01fc39134aad0ae60aef923d4c` |
| PostgreSQL 16 | 1,171 passed / 4,112 assertions / 69.82s | `ee1dd9f752333327a1c3c0d1a05733bb4b6b7fff52ffa82379eefd8e7323f673` |

The emitted union contains 3,843 lines and has SHA-256
`5408eb4fed643e96d9d4eb16bcb548106e10bc2b86b1fc9c890268c89e459313`, byte
identical to `artifacts/2026-08-24-confirmation-union-lines.txt`. Therefore
the backoff-only test change did not alter the covered-line set. Its durable
maps and union are retained as `artifacts/2026-08-24-post-62e51eb-*`. The
closing mutation sweep may consequently exclude unchanged chunks by evidence.
`AuthThrottleFlowTest` executes files in 14 of the 16 chunk groups, so the
exclusion is not based on namespace locality: the changed test is 25 tests and
completes in 1.12 seconds, including both five-submission loops. Its roughly
tenfold headroom over the former one-second deadline makes a false kill require
a mutant to add approximately one second while still terminating; no such row
was observed. Because the reconciliation's findings come from survivors and
gaps, any residual false-kill risk is a missed finding rather than a fabricated
one. The risk is accepted and recorded, not treated as eliminated. Flow and
Throttle remain the semantic candidates for remeasurement; every other chunk
is excluded against this unchanged union and the timing evidence above.

### Post-console coverage provenance

The union committed at `eda87bc` was generated after the console/jobs test
batch with PHPUnit's memory limit temporarily raised from the pinned `128M` to
`512M` so Clover generation could complete. The functional suite passed on all
three engines, while `MemoryLimitScopeTest` deliberately failed because it
asserts the pinned `128M` setting; the setting was restored afterwards. The
line maps are retained as coverage evidence, but this modified-memory
provenance is part of their interpretation and must not be omitted from a
future reproduction.

### Factors confirmation at the post-test SHA

The authoritative rerun used the exact baseline scope and literal command:
`VOUCH_SQLITE_PATH=/tmp/vouch-confirm.sqlite vendor/bin/pest --mutate
--path=src/Factors --no-cache --min=0 --colors=never`. It generated 485
mutations across the same ten RUN files. The retained log is
`artifacts/2026-08-24-factors-confirmation-c0d4677.log` (SHA-256
`8568b4904e558f30870a40c01c6043bf8916fc9a353133cc5ac74fa9c2b5e63e`).

Result: 402 tested, 80 untested, 0 uncovered, and 3 observed timeout rows.
Against the baseline's 395 tested, 80 untested, 6 uncovered, and 4 timeouts,
the six Tier 2 target rows are killed and one additional coverage/timeout row
also moves. The earlier 435-mutation `src/Factors/Drivers` run was narrower
and remains discarded.

The discarded run is itself a measurement-rule example: its plausible
435/358/73 result was rejected because its RUN inventory did not match the
baseline's ten assigned mutant-bearing files. The positive mutation-count and
RUN-count reconciliation rule fired on a confirmation run, where a
comparable-looking aggregate would otherwise have been especially tempting to
trust.

### SQLite engine-equivalent lock mutations

The retained Throttle artifact contains no mutation rows for
`DatabaseAuthThrottleStore:297` or `:328`; the earlier claim that their lock
mutants were killed was an inference from absence. SQLite's grammar compiles
`lockForUpdate()` to an empty lock clause, so every lock call/default mutation
in the affected paths is byte-equivalent under the measuring engine. This is
distinct from `engine-gated`: the code executes, but SQLite cannot distinguish
the original from the mutation. Record these rows as `engine-equivalent` when
the disposition schema is extended, and validate the load-bearing behavior on
PostgreSQL/MySQL separately rather than expecting the SQLite mutation score to
move.

### Additional disposition

`shadowed-by-earlier-guard` is distinct from `instrument-unroutable`,
`never-executed`, and database invariant-unreachable. It applies when an
earlier guard in the same function rejects every input that could reach a
later executable branch. The later branch remains deliberate defensive code
and is retained; the test asserts the earlier guard instead. The three
IntendedDestination parse/authority/path rows are the first examples.

### Assertion-count ladder resolved

The repeated full-suite totals are deliberate. Focused runs at the confirmation
SHA isolated the arithmetic to three files (SQLite / MySQL / PostgreSQL):

| file | SQLite | MySQL | PostgreSQL | reason |
|---|---:|---:|---:|---|
| `tests/Database/ThrottleSchemaTest.php` | 97 | 101 | 101 | four `char(64)` metadata assertions run on non-SQLite engines across the dataset |
| `tests/Database/ScalarThrottleStoreTest.php` | 91 | 90 | 91 | MySQL rejects the negative unsigned insert, so the follow-up store assertion is intentionally skipped |
| `tests/Database/ChallengeAttemptStoreTest.php` | 30 | 29 | 30 | same MySQL unsigned-insert branch skips the follow-up store assertion |

The other focused driver-conditional files were equal across engines. Thus the
full-suite ladder is exactly SQLite `4,108`, MySQL `4,110`, PostgreSQL `4,112`:
PostgreSQL and MySQL each add four schema assertions; MySQL then omits two
follow-up assertions that PostgreSQL retains. No nondeterminism or unexplained
engine drift remains.

## Measurement rules

- Record the exact SHA (`66ac67d`) and the plugin timeout threshold in every
  chunk artifact.
- Report verified kills separately from untested, uncovered, and timeout rows.
  A timeout is unresolved until rerun under the recorded conditions. Reruns
  distinguish observed non-termination under the recorded suite inputs,
  bounded-but-slow execution (a kill once the targeted test completes), and
  genuinely environmental timing noise. Non-termination is not source-only:
  another routed test can throw or return before the loop runs away.
- Six timeout rows have now been examined: five remain observed
  non-termination cases and one was a bounded-but-slow contention-bound
  removal; all six were kills. The Factors confirmation changed one former
  timeout into an ordinary kill when a new routed test reached a terminating
  path. Future confirmation reruns must re-examine timeout rows rather than
  carry timeout rulings forward. This does not authorize crediting the 53
  compact-smoke timeouts, whose identities and causes are unavailable.
- Do not land tests or source changes revealed while ruling chunks. Queue them
  and apply them only after all chunks have been measured, followed by one
  confirming full run at a new, explicitly recorded SHA.
- Membership is `(file, mutator, expression)`, never filename or mutator
  family. A chunk is complete only when its non-compact artifact reconciles
  its `RUN` files to the assigned source inventory.
- Dispositions include `instrument-unroutable` for non-executable mutation
  lines and `engine-gated` for code reachable only on a different database
  engine. Engine-gated coverage must be established by unioning Clover maps
  from SQLite, MySQL, and PostgreSQL; SQLite alone cannot classify it.
- Exception-message concatenation survivors are a standing `no-action`
  disposition when the throwing guard itself is killed: asserting prose would
  couple tests to explanatory text rather than behavior. A bare throw that
  generates no mutation is instead `unmutatable`; unlike an unroutable line,
  it still requires ordinary test coverage when the guard carries a security
  or state-transition contract.
- A chunk command must assert a positive mutation count and reconcile its `RUN`
  count to the assigned mutant-bearing files. `--min=0` otherwise permits a
  misspelled scope to exit successfully with `0 Mutations for 0 Files`.
- Record the literal command line, not a Markdown-escaped namespace spelling.
  The class filter is a prefix match on the `namespace` declaration and does
  reach nested namespaces, but it is escaping-sensitive: a single-quoted
  `--class='Fissible\\Vouch\\Kernel'` passes a literal double backslash and
  matches nothing anywhere. Prefer the directory-literal `--path=src/Kernel`,
  which has no escaping hazard and mirrors the chunk assignment.

## Chunk assignment

| chunk | assigned source directories | source files | elapsed / timeout | status at `66ac67d` |
|---|---|---:|---|---|
| Delivery | `src/Delivery/` | 14 | 134.51s / 38.36s | rerun classified: 229 mutations / 7 RUN files; 164 tested, 64 executed survivors, 1 never-executed, 0 timeouts |
| Flow | `src/Flow/` | 10 assigned / 5 mutant-bearing | 243.64s + 70.97s / 38.52s | rerun classified: AuthFlow plus 9-file remainder; 354 mutations total, 333 tested, 20 executed survivors, 1 never-executed; remainder has 61 tested, 8 survivors, 0 gaps/timeouts |
| Throttle | `src/Throttle/` | 13 assigned / 7 mutant-bearing | 3,047.11s / 38.52s | rerun measured: 865 mutations; 739 tested, 86 untested, 40 uncovered, 0 timeouts; verified score 85.43% |
| Kernel | `src/Kernel/` | 26 | 161.87s / 37.85s | measured: 236 mutations / 13 RUN files; 205 tested, 5 untested, 26 uncovered, 0 timeouts |
| Console | `src/Console/` | 8 | 88.94s / 38.03s | measured: 181 mutations / 8 RUN files; 125 tested, 34 untested, 22 uncovered, 0 timeouts |
| Notifications | `src/Notifications/` | 9 assigned / 4 mutant-bearing | 153.02s / 38.52s | measured: 183 mutations; 150 tested, 24 untested, 8 uncovered, 1 timeout |
| Core / data and boundaries | explicit sub-runs below | 82 | measured by sub-run | all 14 sub-runs measured; no aggregate run substituted for a sub-run |

Core sub-runs are deliberately itemized because routing breadth makes one
82-file estimate misleading:

| sub-run | source files | status |
|---|---:|---|
| Attempts | 10 | measured: 87 mutations; 62 tested, 25 untested, 0 uncovered, 0 timeouts |
| Contracts | 9 | measured: 0 mutations / 9 zero-mutant files |
| Enrollment | 3 | measured: 34 mutations; 18 tested, 16 untested, 0 uncovered, 0 timeouts |
| Factors | 16 | measured: 485 mutations; 395 tested, 80 untested, 6 uncovered, 4 timeouts |
| Http | 7 | measured: 167 mutations; 140 tested, 18 untested, 9 uncovered, 0 timeouts |
| Jobs | 1 | measured: 13 mutations; 8 tested, 3 untested, 2 uncovered; 0 timeouts |
| Models | 15 | measured: 142 mutations; 135 tested, 4 untested, 3 instrument-unroutable, 0 timeouts |
| Persistence | 3 | measured: 42 mutations; 9 tested, 30 untested, 3 never-executed, 0 timeouts |
| Recovery | 2 | measured: 43 mutations; 43 tested, 0 untested, 0 uncovered, 0 timeouts |
| Secrets | 2 | measured: 17 mutations; 5 tested, 12 untested, 0 uncovered, 0 timeouts |
| Sessions | 5 | measured: 46 mutations; 38 tested, 8 untested, 0 uncovered, 0 timeouts |
| Support | 6 | measured: 119 mutations; 79 tested, 25 untested, 14 uncovered, 1 timeout |
| Tenancy | 1 | measured: 0 mutations / 1 zero-mutant file |
| root (`Vouch.php`, `VouchServiceProvider.php`) | 2 | measured: 148 mutations; 114 tested, 26 untested, 8 never-executed, 0 timeouts |

The assignment covers all 162 source files and therefore cannot silently omit
the nine remaining Flow files. The **91-file figure is provisional**: the
authoritative subset will be the intersection of this inventory with the
`RUN` lists emitted by the seven non-compact chunk measurements, and the ledger
must replace the provisional total with that sum before reconciliation can
close. Zero-mutant files are retained here as explicit zero-mutant evidence
rather than disappearing from the ledger.

The pending zero-gap confidence check covers seven sub-runs and 32 files:
Attempts, Contracts, Enrollment, Recovery, Secrets, Sessions, and Tenancy.
The union predicts no never-executed rows in those scopes; any uncovered rows
should be instrument-unroutable, with substantive findings appearing only as
executed survivors.

## Valid measurements

### Delivery

- Command scope: `Fissible\\Vouch\\Delivery`
- SHA: `66ac67d`
- Baseline: 1,161 tests, file-backed SQLite, 31.41s
- Timeout threshold: 37.69s (baseline + `max(5s, 20%)`)
- Result: 229 mutations / 7 files; 164 tested, 64 untested, 1 uncovered,
  0 timeouts; verified score 71.62%
- Classification rerun: 64 executed-and-survived and 1 never-executed. The
  never-executed row is `DatabaseDeliveryEconomics.php:258`; the committed
  union line-set also excludes that line, so it is not engine-gated.
- Rerun artifacts: `artifacts/2026-08-24-delivery-rerun-66ac67d.log`
  (SHA-256 `abd311e70d4f441fa1e82ad9ad6d4d6f04bf2516af7b6a237451f45d025472f2`)
  and `artifacts/2026-08-24-delivery-rerun-classification.json` (SHA-256
  `a9dfaf8e8e99b501e6794199d727b1830d09ef2d7a1ee871f9717d7dab1904c6`).

### Flow / AuthFlow

- Command scope: `Fissible\\Vouch\\Flow\\AuthFlow`
- SHA: `66ac67d`
- Baseline: 1,161 tests, file-backed SQLite, 30.68s
- Timeout threshold: 36.82s
- Result: 285 mutations / 1 file; 272 tested, 12 untested, 1 uncovered,
  0 timeouts; verified score 95.44%
- Classification rerun: 12 executed-and-survived and 1 never-executed. The
  never-executed row is `AuthFlow.php:717`; the committed union line-set also
  excludes it, confirming the dead path on all three measured engines.
- Rerun artifacts: `artifacts/2026-08-24-authflow-rerun-66ac67d.log`
  (SHA-256 `3e6d21e81c2a1bc56e6c20ddcba2f2fb8c9b9108121f29b56db8f184d670ea49`)
  and `artifacts/2026-08-24-authflow-rerun-classification.json` (SHA-256
  `9c8f2fd67a7d638d95d41fd9a9f774a5bed5f6d36ace643093227e3fa1663760`).
- This does **not** close Flow. `VerificationEqualizer`, `ScreenBuilder`, and
  the seven remaining result/request classes require their own RUN evidence.

The `AuthFlow.php:717` row is ruled `invariant-unreachable`, not dead merely
because coverage missed it: both live callers pass their value into
`AuthSuccess`, whose public `int $userId` contract makes the nullable branch
unreachable. If that caller contract is relaxed to `?int`, the ruling must be
revisited. The Delivery `row() === null` defensive row is the single
`DatabaseDeliveryEconomics.php:250` branch; earlier references to `:258` were
line drift after the simplification, not a second row.

### Flow remainder

- Literal command: `vendor/bin/pest --mutate --path=src/Flow/AuthSuccess.php,src/Flow/Authenticated.php,src/Flow/Continuing.php,src/Flow/FlowRequest.php,src/Flow/FlowResult.php,src/Flow/RecoveryGraceStarted.php,src/Flow/ScreenBuilder.php,src/Flow/UnknownFlowResult.php,src/Flow/VerificationEqualizer.php --no-cache --min=0`
- SHA/source-equivalence guard: `a73aa6d`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 31.25s;
  timeout threshold 37.50s.
- Result: 69 mutations / 5 RUN files; 61 tested, 8 untested, 0 uncovered,
  0 timeouts; elapsed 70.97s; verified score 88.41%.
- The nine-file prediction held: no remaining Flow row was absent from the
  unioned executed-line set. The eight survivors are message-fragment
  concatenation mutants only: six in `ScreenBuilder.php:91` and two in
  `UnknownFlowResult.php:23`. `VerificationEqualizer` and the DTO/result
  classes produced no surviving rows. Keep the eight as one queued
  message-only ruling; do not add tests during the pinned measurement.
- Row-level artifacts: `artifacts/2026-08-23-flow-remainder-66ac67d.log`
  (SHA-256 `47c6f8800caae6368444f088a297a1917ca2391416581ece93fa0f9cf078d87e`)
  and `artifacts/2026-08-23-flow-remainder-classification.json` (SHA-256
  `12e7c8992bebdfe4b544da9f9d983fee5e1d4f2fb91bea91acded790840fd2e9`).

### Throttle

- Command scope: `Fissible\\Vouch\\Throttle`
- SHA: `66ac67d`
- Baseline: 1,161 tests, file-backed SQLite, 31.07s
- Timeout threshold: 37.28s
- Result, first run: 865 mutations / 7 mutant-bearing files; 736 tested, 89
  untested, 40 uncovered, 0 timeouts; 3,165.85s; threshold 37.28s.
- Result, retained rerun: 865 mutations / 7 RUN files; 739 tested, 86
  untested, 40 uncovered, 0 timeouts; 3,047.11s; threshold 38.52s; verified
  score 85.43%.
- Assigned inventory remains 13 files; six produced zero mutations and are
  retained as zero-mutant evidence. The mutant-bearing RUN set is
  `ThrottleKey`, `ThrottleSubject`, `DatabaseAuthThrottleStore`,
  `IdentifierThrottle`, `ThrottleConfiguration`, `ThrottleReporter`, and
  `IpCanonicalizer`.
- Same SHA, instrument, mutation total, and RUN set produced a three-row
  tested/untested flip between the two runs. Coverage-derived uncovered rows
  were identical; kill/survive outcomes are not fully reproducible in the
  lock-wait-heavy `DatabaseAuthThrottleStore` path. The rerun log and manifest
  are the row-level artifact; up to three timing-sensitive untested rows should
  be individually reconfirmed before adding tests or rulings.
- Rerun row artifacts: `/tmp/vouch-throttle-66ac67d-rerun-clean.log` and
  `/tmp/vouch-throttle-66ac67d-rerun-manifest.json`.
- Rerun uncovered/untested distribution: `DatabaseAuthThrottleStore` 8/49,
  `ThrottleConfiguration` 22/25, `ThrottleReporter` 10/10, and
  `IpCanonicalizer` 0/2. The unioned engine map is load-bearing for the
  DatabaseAuthThrottleStore branch; the remaining uncovered rows are not
  presumed engine-gated.
- The 3,165.85s elapsed time validates the scheduling warning: routing breadth,
  not mutation count, dominates this chunk.
- The initial hypothesis that the 40 uncovered rows were caused by observe-mode
  defaults is rejected: 17 test files exercise enforce-mode behavior. The
  uncovered rows therefore require individual routing, invariant-unreachable,
  or missing-test dispositions.
- Ruling work must record the expected routing movement explicitly. As with
  Delivery, tests added or routed to an uncovered expression may move rows into
  `UNTESTED`; that is an instrument becoming more honest, not a regression.
  Throttle starts at 89 untested / 40 uncovered, and those figures must be
  compared with the final post-routing artifact rather than read as a trend in
  implementation quality.

### Closing Flow and Throttle sweep

Commit `3210dad` ran the two semantic candidates at the post-flake-fix source
guard (`62e51eb`), using non-compact path-scoped commands and retained logs.
Flow reproduced its baseline exactly: 354 mutations across 6 RUN files, 333
tested, 20 untested, and 1 uncovered. Throttle reproduced the 865-mutation,
7-RUN inventory and ended at 735 tested, 90 untested, and 40 uncovered, with no
timeouts. The four tested-to-untested movements were:

- `DatabaseAuthThrottleStore:409` SQLite driver dispatch;
- `DatabaseAuthThrottleStore:662` SQLite driver dispatch;
- `DatabaseAuthThrottleStore:642` backoff-cap comparison; and
- `ThrottleConfiguration:364` validation-message prose.

The first three are the expected trade from replacing the one-second CAPTCHA
test deadline with 30 seconds: the old test accidentally discriminated small
backoff/driver changes through deadline expiry. They are now queued for direct,
deterministic tests rather than restored to a flaky oracle. The Recovery branch
at `DatabaseAuthThrottleStore:583` was still mechanically never-executed on
all engines at this historical point; the later refactor and rerun below
resolve its arm swaps and leave only the intentionally shadowed call site.

Artifacts: Flow log/classification SHA-256
`14dc8aec1ba5d02a9feef8029b74ee2969045c95b03a759e43664fa85e97f0d9` /
`2b8c08602f425d29db2a27debdde07ef48b1717a147462e34f7b45d03bc739fc`; Throttle
log/classification SHA-256
`0ed63292e5983d77b489cb3173ef82abd24e56c79f70e4af203405cc027a92fd` /
`d0d0378d8a373eceb343a0b6333d2766c39dbebe4a0aa6079ba24b84ff4b0edd`.

The first expiry follow-up briefly used a reflection test to invoke the
private `sharedState()` method, but that was rejected: it can kill mutants by
bypassing every production caller and would make the mutation score less
truthful. The production call graph makes this branch
`shadowed-by-caller-guard`: `preflightShared()` returns before `sharedState()`
for expired rows, while `recordScalarFailure()` consults the result only for
`BackedOff` and then discards it after incrementing. The duplicated posture
expression is now centralized in `expiredPosture()`. That helper is returned
through `preflightShared()` and is covered by its existing data-provider test,
so its two arm-swap mutants are now expected to be killed. Only the separate
`sharedState()` call site remains shadowed: its return is discarded by
`recordScalarFailure()`, so a RemoveEarlyReturn/RemoveMethodCall mutant there
remains equivalent-by-call-context. The earlier all-three-row equivalence
disposition applied to the pre-refactor structure and is superseded by
`212212a`.

The post-refactor Throttle run confirmed the expected footprint: 863 mutations
(`735 tested + 90 untested + 38 uncovered`) across the same 7 RUN files, with
the two arm-swap mutants killed and the residual `sharedState()` removal at
line 581 uncovered. That row is intentionally mechanically never-executed:
all production callers either return the posture before `sharedState()` or
discard its non-`BackedOff` result. Its human disposition remains
shadowed-by-caller-guard / equivalent, so future `never-executed` output for
this exact row is expected and must not be queued as a test gap.

The first isolated follow-up batch (`57cc122`) added deterministic backoff
schedule assertions. Its Throttle rerun still reports 865 mutations / 7 RUN
files, 735 tested, 90 untested, 40 uncovered, and 0 timeouts. The baseline row
diff is empty: the test executes the schedule but does not discriminate the
survivors. `DatabaseAuthThrottleStore:638` and `:642` are now both classified
as `idempotent-under-clamp`: widening either guard permits an extra iteration
or assignment, but the following `min()` restores the same returned offset.
No second 50-minute rerun is required to decide these rows. `:657` is likewise
a language-semantic equivalent: PHP parses `modify('5 seconds')` and
`modify('+5 seconds')` identically. The stronger window-clamp assertion is
committed separately as `a438e33`; it remains useful schedule coverage even
though these two mutants are observationally inert.

The later Throttle gap batch at `0ecdd09` added the strict boolean-coercion and
never-attempted-released fixtures. Its rerun retained the same 7-file scope;
the current classification contains 106 rows: 91 executed-and-survived, 10
engine-gated, 3 instrument-unroutable, and 2 never-executed. The baseline diff
reports 22 removed and 0 added. The earlier 16-row result under-reported
duplicate line-key occurrences, which are now counted by ordinal.

The two remaining Throttle never-executed rows are already ruled: the
`sharedState()` call-site row at `:581` is shadowed by its caller guard, and
the `DateTimeInterface` branch at `:881` is defensive for a driver type not
returned by any matrix engine. No actionable never-executed gap remains in
Throttle.

### Kernel

- Literal command: `vendor/bin/pest --mutate --path=src/Kernel --no-cache --min=0`
- Source-equivalence guard: current documentation HEAD `aa04377` has no diff
  from baseline `66ac67d` under `src/`, `tests/`, dependencies, config, or
  database paths.
- Baseline: 1,161 tests, file-backed SQLite, 31.54s
- Timeout threshold: 37.85s
- Result: 236 mutations / 13 RUN files; 205 tested, 5 untested, 26
  uncovered, 0 timeouts; elapsed 161.87s; verified score 86.86%
- The initial `--class='Fissible\\Vouch\\Kernel'` probe generated zero
  mutations because single quotes passed a literal double backslash, which
  `preg_quote` turned into a pattern requiring two backslashes in the source.
  The class filter itself prefix-matches nested namespaces correctly; the same
  spelling matches nothing for any chunk, which is why the Delivery measurement
  could not have used it. The probe exited successfully under `--min=0` and is
  explicitly discarded; the path-scoped run is the authoritative Kernel
  measurement.
- Coverage routing identifies 25 of the 26 uncovered rows as
  **instrument-unroutable** declaration/match lines (14 `TransitionRules`
  constant declarations, 10 `FactorStrength` enum-case declarations, and the
  `SatisfiabilityEvaluator` match line). The remaining uncovered row is the
  genuine `ErrorShaper::strictLockRetry()` disclosure gap; queue a focused test
  for it, but do not land it during measurement.
- The five untested rows are on executed lines and remain genuine survivor
  candidates for individual classification.
- Mechanical classification artifacts: `artifacts/2026-08-24-kernel-66ac67d.log`
  (SHA-256 `c1344591f4657c44667a7b5277f07abcd70aafa8402b8726bcb065cc55a80228`)
  and `artifacts/2026-08-24-kernel-classification.json` (SHA-256
  `4a03f5b8b7d7d28a3b035a4f85ac826fa16381f1539a0aa429add6ab3fd956bb`). The
  tool reproduces 25 instrument-unroutable, 1 never-executed, and 5
  executed-and-survived rows with no contested entries.

## Reconciled disposition totals

The 19 committed classification artifacts contain 629 rows in total: 480
executed-and-survived, 88 never-executed, 45 instrument-unroutable, 10
engine-gated, and 6 separately retained timeouts. Of these, 235 are
exception-message concatenation mutants covered by the standing no-action
rule. The totals are a reconciliation check, not a mutation score; timeouts
remain unresolved until individually classified.

## Queued cross-chunk findings

These are recorded before the remaining chunks run and must not be silently
reclassified as instrumentation artifacts:

- `DatabaseAuthThrottleStore.php:415–419` is engine-gated. SQLite always takes
  the SQLite branch; the committed-row path is exercised only by MySQL and
  PostgreSQL. Three engine-specific Clover maps must be unioned before ruling.
- `VouchDoctorCommand.php` has no coverage for exit 0, exit 2, human/table
  output, or per-check exception fallback. Its command-specific exit contract
  needs tests for all three outcomes and both render modes.
- `OtpOutboxDelivery.php` has no terminalization proof for
  `target_unavailable`, `legacy_unparseable`, `country_not_allowed`, or
  `spend_ceiling`, nor for the pre-provider `InvalidArgumentException` and
  positive-cost guards. Queue an end-to-end assertion that a `SpendCeiling`
  reservation refusal records `spend_ceiling` on the outbox row.
- `VouchPruneCommand.php:130` and `OtpQueueDispatcher.php:75` are defensive
  invariant-unreachable throws and should be dispositioned as such, not left
as unexplained uncovered rows.

### Console

- Literal command: `vendor/bin/pest --mutate --path=src/Console --no-cache --min=0`
- SHA/source-equivalence guard: current documentation HEAD `f4a5c00`, no
  guarded-path diff from `66ac67d`.
- Baseline: 1,161 tests, file-backed SQLite, 31.69s; timeout threshold 38.03s.
- Result: 181 mutations / 8 RUN files; 125 tested, 34 untested, 22 uncovered,
  0 timeouts; elapsed 88.94s.
- Definitive classifier used the Console SQLite map plus the pinned MySQL and
  PostgreSQL union: 34 executed-and-survived, 16 never-executed, and 6
  instrument-unroutable. The predicted `VouchDoctorCommand.php:84` row is
  `never-executed` across the union, not engine-gated. The artifact is
  `artifacts/2026-08-22-console-classification.json` (SQLite map SHA-256
  `f97315f0fae6b1647f7e0e1bddbd51c052334fa55ef87215b39aedd27cb3867a`).

### Notifications

- Literal command: `vendor/bin/pest --mutate --path=src/Notifications --no-cache --min=0`
- SHA/source-equivalence guard: documentation HEAD `c194b7d`, no guarded-path
  diff from `66ac67d`.
- Baseline: 1,161 tests, file-backed SQLite, 32.11s; timeout threshold 38.52s.
- Result: 183 mutations / 4 RUN files; 150 tested, 24 untested, 8 uncovered,
  1 timeout; elapsed 153.02s. The timeout is recovered positionally from its
  `RUN` heading as `OtpOutboxDelivery.php:175` `PostIncrementToPostDecrement`.
- The committed classifier used the Notifications SQLite map plus the pinned
  MySQL/PostgreSQL union: 24 executed-and-survived, 8 never-executed, and 1
  recovered timeout. The
  eight never-executed rows are the predicted `OtpOutboxDelivery`
  terminalization causes. The 16 executed survivors in that class are not
  evidence that `DeliverOtpChallenge::failed()` is discriminated: that class is
  in `src/Jobs/` and will be measured in the Jobs/Core sub-run.
- Artifact: `artifacts/2026-08-22-notifications-classification.json` (SQLite
  map SHA-256 `bc502c4b33b531784bacd681e54162c5dc72e8cb1f7f6d921bb1ccd8b5fd0040`;
  corrected classifier SHA-256
  `902dd8c5c2c8aad47fdce84a8b5defb17ff1bb2181c50c85d5458ef0ee0d884a`).
- The recovered timeout is a structural non-termination: mutating
  `for ($attempt = 0; $attempt < 3; $attempt++)` to post-decrement runs the
  counter `0, -1, -2, ...` and can never terminate. It is dispositioned as
  `killed-by-non-termination`, not rerun indefinitely as an environmental
  timeout. The committed classifier retains the mechanical
  `timeout-unresolved` state; this explicit ruling is the human disposition.

### Core / Jobs

- Literal command: `vendor/bin/pest --mutate --path=src/Jobs --no-cache --min=0`
- SHA/source-equivalence guard: `bda06d4`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 30.96s;
  timeout threshold 37.15s.
- Result: 13 mutations / 1 RUN file; 8 tested, 3 untested, 2 uncovered,
  0 timeouts; elapsed 6.27s; verified score 61.54%.
- The two `$tries = 5` declaration rows are instrument-unroutable: a declared
  retry count cannot be certified by an executable-line mutation. The three
  executed survivors form one queued retry-and-missing-evidence ruling. At
  `handle():32`, forcing the missing-outbox guard true survives, so the
  not-found redispatch path is untested; `handle():33` shows the one-second
  delay is not asserted. At `failed():46`, removing `?->` survives because no
  test observes a vanished outbox row. The null row is currently classified as
  `WorkerFailure` by the null comparison, but disappearance does not prove
  whether a provider was contacted, so that terminal attribution needs an
  explicit decision and test. The positive provider-attempted and
  provider-never-attempted outcomes are asserted; this ruling covers the
  missing-evidence paths rather than reopening those branches.
- Artifacts: `artifacts/2026-08-23-jobs-66ac67d.log` (SHA-256
  `da3c99b9f9b03bc5a11fec9466fcf00894df2bcfb8501858091a325a594bae97`) and
  `artifacts/2026-08-23-jobs-classification.json` (SHA-256
  `bb32ffa612641b454047f15adba293377e4925de0af1136ff932d78714e10e5a`).

### Core / Factors

- Literal command: `vendor/bin/pest --mutate --path=src/Factors --no-cache --min=0`
- SHA/source-equivalence guard: `cf2addd`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 31.05s;
  timeout threshold 37.26s.
- Result: 485 mutations / 10 RUN files; 395 tested, 80 untested, 6
  uncovered, 4 timeouts; elapsed 427.39s; verified score 81.44% when the
  four timeouts are kept unresolved (82.27% is the plugin display that credits
  them).
- The six uncovered rows are all null-user early-return guards in
  `RecoveryCodeFactor`, `OtpFactor`, `TotpFactor`, and `PasswordFactor`; they
  are present executable lines with no test reaching the branch, not engine
  artifacts. The predicted `ChallengeIssuer:78` cross-attempt guard generated
  no mutation and therefore has no row-level evidence yet.
- The four timeout rows are structural non-termination: post-decrementing the
  bounded loops at `RecoveryCodeFactor:140`, `RecoveryCodeFactor:248`,
  `OtpFactor:459`, or changing the TOTP offset loop at `TotpFactor:279` to
  post-increment makes the loop fail to reach its terminating condition. They
  are dispositioned as killed-by-non-termination rather than rerun.
- The 80 executed survivors require a later ruling pass; many are exception
  message concatenations, while the factor/credential and TOTP decision rows
  need mechanism-level review. Artifacts: `artifacts/2026-08-23-factors-66ac67d.log`
  (SHA-256 `7f06da059ea88044f17956c2cbd0579300771d5883174357f7e61cdbe1e041d8`)
  and `artifacts/2026-08-23-factors-classification.json` (SHA-256
  `6245eb4a88163287dc05428378dc805b5cc0921efabe66e52b09f79ab7f85ea7`).

### Core / Support

- Literal command: `vendor/bin/pest --mutate --path=src/Support --no-cache --min=0`
- SHA/source-equivalence guard: `bb549ed`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 31.46s;
  timeout threshold 37.75s.
- Result: 119 mutations / 4 RUN files; 79 tested, 25 untested, 14
  uncovered, 1 timeout; elapsed 309.14s; verified score 67.23% after resolving
  the bounded-but-slow timeout below.
- The 14 uncovered rows are genuine never-executed branches: the PostgreSQL
  rollback-restoration predicate in `BoundedLockWait`, plus the unsupported
  driver and scalar/timestamp fallback paths. No row was engine-gated by the
  union. The one timeout is `BoundedLockWait:65 RemoveMethodCall`; removing
  `writeSeconds()` allows the real contention path to wait for the ambient
  47-second setting. A targeted rerun of the mutated source against
  `BoundedLockWaitContentionTest` completed in 49.15s and failed its explicit
  `<10s` assertion, so this is `killed-by-bounded-slow`, not an unresolved or
  structural timeout.
- The 25 executed survivors include exception-message fragments (covered by
  the standing message-prose rule), the `DatabaseRowLock` predicate-building
  rows at lines 31–32, and behavioral/cast rows in `BoundedLockWait` and
  `DatabaseTime` that need individual review. The row-lock survivors are
  carried into the existing throttle-lock mechanism ruling rather than
  treated as independent test gaps.
- Artifacts: `artifacts/2026-08-23-support-66ac67d.log` (SHA-256
  `bae57b4f5d5893e1860dc73a428eb6e7d8a4c881fe2c129aafe1ae09b3539ec0`) and
  `artifacts/2026-08-23-support-classification.json` (SHA-256
  `7c9e4fcad72859eb9fd5a2ae0c23e34d3e8d1d8f4faa1dbf50a8af4a32315558`).

### Core / Contracts

- Literal command: `vendor/bin/pest --mutate --path=src/Contracts --no-cache --min=0`
- SHA/source-equivalence guard: `dc6c022`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 30.86s.
- Result: 0 mutations / 0 RUN files; all 9 assigned contract files retained as
  explicit zero-mutant evidence. This is genuine: the files are bare interface
  declarations with no method bodies or mutable constructs, not an empty scope.
  There are no mutation rows to classify.
- Artifact: `artifacts/2026-08-24-contracts-66ac67d.log` (SHA-256
  `4742fbf169448ee73770eeaf5ab4ee9d0f511f1a00e65904afe8604a1f825349`).

### Core / Enrollment

- Literal command: `vendor/bin/pest --mutate --path=src/Enrollment --no-cache --min=0`
- SHA/source-equivalence guard: `4e46fc9`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 30.82s;
  timeout threshold 36.98s.
- Result: 34 mutations / 2 RUN files; 18 tested, 16 untested, 0 uncovered,
  0 timeouts; elapsed 239.04s; verified score 52.94%.
- The zero-gap prediction held: no never-executed rows. The 16 survivors
  divide into exception-code/message prose in `EnrollmentRefused` (covered by
  the standing message rule) and substantive `EnrollmentGuard` contract rows:
  injected `DatabaseRowLock` being discarded (`:50`), changing the minimum
  bounded wait (`:122`), and removing either lock-key predicate (`:126`). The
  latter rows join the existing lock/constructor-injection ruling queue.
- Artifacts: `artifacts/2026-08-24-enrollment-66ac67d.log` (SHA-256
  `52213ced456e484d25003c75ff6b22feac063c79618da4c5fc32dbee67325ffa`) and
  `artifacts/2026-08-24-enrollment-classification.json` (SHA-256
  `65d651fed95014c3be72c8c491806447f1a974ca950a4789c6f21e6db07c6976`).

### Core / Recovery

- Literal command: `vendor/bin/pest --mutate --path=src/Recovery --no-cache --min=0`
- SHA/source-equivalence guard: `dff29e8`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 30.52s;
  timeout threshold 36.62s.
- Result: 43 mutations / 2 RUN files; 43 tested, 0 untested, 0 uncovered,
  0 timeouts; elapsed 21.92s; verified score 100.00%.
- The seven-sub-run zero-gap prediction held: no coverage-negative rows or
  survivors were emitted.
- Artifacts: `artifacts/2026-08-24-recovery-66ac67d.log` (SHA-256
  `5fc4f1b5db01da67fabba42ec58ea979a0c4bf99b316ec18bb2a6bf402c426df`) and
  `artifacts/2026-08-24-recovery-classification.json` (SHA-256
  `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570`).

### Core / Secrets

- Literal command: `vendor/bin/pest --mutate --path=src/Secrets --no-cache --min=0`
- SHA/source-equivalence guard: `dff29e8`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 30.71s;
  timeout threshold 36.85s.
- Result: 17 mutations / 2 RUN files; 5 tested, 12 untested, 0 uncovered,
  0 timeouts; elapsed 6.09s; verified score 29.41%.
- All 12 survivors are exception-message concatenations in `OneTimeSecret`
  and `SecretAlreadyRevealed`; they join the standing message-prose ruling.
  The union map marks their lines unmapped, but plugin `UNTESTED` state takes
  precedence and they remain executed-and-survived (contested).
- Artifacts: `artifacts/2026-08-24-secrets-66ac67d.log` (SHA-256
  `52537f20daac7a4ef20feaccc7f606fefda4a7a43a9b7392706f43a84cb56e2c`) and
  `artifacts/2026-08-24-secrets-classification.json` (SHA-256
  `01a4a5df55aa6dca01ffa4e0c9b8d17608e13cdd65d1da1f186c4ba20e5037bc`).

### Core / Sessions

- Literal command: `vendor/bin/pest --mutate --path=src/Sessions --no-cache --min=0`
- SHA/source-equivalence guard: `dff29e8`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 30.58s;
  timeout threshold 36.70s.
- Result: 46 mutations / 3 RUN files; 38 tested, 8 untested, 0 uncovered,
  0 timeouts; elapsed 46.07s; verified score 82.61%.
- The eight survivors are all concatenation/message-prose rows in
  `SessionRotationFailed`; they join the standing message-prose ruling.
- Artifacts: `artifacts/2026-08-24-sessions-66ac67d.log` (SHA-256
  `a0d5d76fb566df3c5fecac12c2566058d692468ec78fd4d82c8bd13c2894886c`) and
  `artifacts/2026-08-24-sessions-classification.json` (SHA-256
  `8e7d82dadefad7c09b871d948d2a7c24d6a4324972744de77799277b205964f1`).

### Core / Tenancy

- Literal command: `vendor/bin/pest --mutate --path=src/Tenancy --no-cache --min=0`
- SHA/source-equivalence guard: `dff29e8`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 30.80s.
- Result: 0 mutations / 0 RUN files; the assigned tenancy file is retained as
  explicit zero-mutant evidence. This is genuine: `NullTenantResolver` has a
  single `return null;` body and no mutable construct for the plugin to emit,
  rather than being a mis-scoped run.
- Artifact: `artifacts/2026-08-24-tenancy-66ac67d.log` (SHA-256
  `3d623f547577a712eef3e101c1f11b8aac559d70f0729c8ebb988ab93c000f92`).

### Core / Attempts

- Literal command: `vendor/bin/pest --mutate --path=src/Attempts --no-cache --min=0`
- SHA/source-equivalence guard: `6b6ac21`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 30.67s;
  timeout threshold 36.80s.
- Result: 87 mutations / 8 RUN files; 62 tested, 25 untested, 0 uncovered,
  0 timeouts; elapsed 55.48s; verified score 71.26%.
- The zero-gap prediction held: no never-executed rows. The 25 survivors are
  executed-and-survived; they include message-prose rows in attempt outcome
  exceptions and substantive `DatabaseAttemptStore` rows for mutation-list
  reindexing and duplicate-target detection. The `seen[$target] = true` to
  `false` survivor is equivalent under the surrounding `isset()` check; the
  reindexing survivor remains a contract row requiring review. The remaining
  exception-code and message rows join the standing no-action ruling.
- The seven-sub-run confidence set (Attempts, Contracts, Enrollment, Recovery,
  Secrets, Sessions, Tenancy; 32 assigned files) is now fully measured. Its
  zero-gap prediction held for coverage-negative rows, but it produced
  substantive survivors in Enrollment and Attempts, so the set is not a
  blanket no-action result.
- Artifacts: `artifacts/2026-08-24-attempts-66ac67d.log` (SHA-256
  `cf0693abf56afdf3136e2a53028e5f88870ae1fe5ec5e70203765d35b05ec007`) and
  `artifacts/2026-08-24-attempts-classification.json` (SHA-256
  `f3bfcd50e45b364afd0bee3cbc0d3e1f3fbd66c065379b3b4fa06c7dc72f65d4`).

### Core / root

- Literal command: `vendor/bin/pest --mutate --path=src/Vouch.php,src/VouchServiceProvider.php --no-cache --min=0`
- SHA/source-equivalence guard: `e6f1a1b`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 30.51s;
  timeout threshold 36.61s.
- Result: 148 mutations / 2 RUN files; 114 tested, 26 untested, 8
  never-executed, 0 timeouts; elapsed 1,942.50s; verified score 77.03%.
- The middleware-group guard's line-389 rows are message prose only and join
  the standing no-action rule. The `challengeFactors()` type guard at
  lines 422–424 produced no mutation rows because it is a bare throw; it is
  coverage-dead and mutation-invisible, so it remains an `unmutatable`
  security/configuration contract. The two line-438 `return false` rows are
  genuine never-executed doctor-argv handling. The remaining 26 survivors
  include doctor-command argument scanning, queue configuration, and existing
  API/configuration behavior; they require row-level review rather than a
  blanket disposition.
- Artifacts: `artifacts/2026-08-24-root-66ac67d.log` (SHA-256
  `a54f8918fabb3257d607ef0c05f911489a881848bba54197e73d8be5293b49f6`) and
  `artifacts/2026-08-24-root-classification.json` (SHA-256
  `045f75db760468e4bd2206704b739adfecaf3a52c499b68f7988974dc76635c66`).

### Core / Http

- Literal command: `vendor/bin/pest --mutate --path=src/Http --no-cache --min=0`
- SHA/source-equivalence guard: `5e30efd`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 32.75s;
  timeout threshold 39.30s.
- Result: 167 mutations / 7 RUN files; 140 tested, 18 untested, 9 uncovered,
  0 timeouts; elapsed 112.19s; verified score 83.83%.
- Classification: 18 executed-and-survived, 3 never-executed, and 6
  instrument-unroutable. The three never-executed rows are the predicted
  `IntendedDestination` rejection returns at lines 83, 89, and 96; queue one
  focused rejection-path test. The six unroutable rows are the `match (true)`
  declarations in the two flow handlers and `AssuranceComparator::ORDER`
  constant removals. The remaining survivors require row-level review; do not
  infer that redirect or assurance contracts are covered from their aggregate
  score.
- Artifacts: `artifacts/2026-08-24-http-66ac67d.log` (SHA-256
  `74f65c6672e2056796b85df73018f64889415f0b1599ce08029dc1c83db094bd`) and
  `artifacts/2026-08-24-http-classification.json` (SHA-256
  `49d662d7b2976cb6a778f13348a1b129bb18c9fa547ffc235bd1802377045852`).

### Core / Persistence

- Literal command: `vendor/bin/pest --mutate --path=src/Persistence --no-cache --min=0`
- SHA/source-equivalence guard: `fba0833`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 31.94s;
  timeout threshold 38.33s.
- Result: 42 mutations / 3 RUN files; 9 tested, 30 untested, 3
  never-executed, 0 timeouts; elapsed 21.97s; verified score 21.43%.
- The three never-executed rows are the `ChallengeTargetViolation::decoyNamedTarget()`
  message concatenations. The guard's bare throw at `GuardsChallengeTarget`
  remains mutation-invisible; together they are the decoy-named-target
  security contract and should be covered by one focused test rather than
  inferred from the mutation score. The other 30 survivors are exception
  message prose and join the standing no-action ruling.
- Artifacts: `artifacts/2026-08-24-persistence-66ac67d.log` (SHA-256
  `3c99d9fbb24dfabc695094b387fd7b7730c04273b092a01df05f3acc66b0c31e`) and
  `artifacts/2026-08-24-persistence-classification.json` (SHA-256
  `2bac85515813fbab7965a515764f89a6c907a09d33e121b5ac5e55dc2e7386aa`).

### Core / Models

- Literal command: `vendor/bin/pest --mutate --path=src/Models --no-cache --min=0`
- SHA/source-equivalence guard: `43d6d07`, with no guarded-path diff from
  `66ac67d` immediately before the run.
- Baseline: 1,161 tests, 4,092 assertions, file-backed SQLite, 31.68s;
  timeout threshold 38.02s.
- Result: 142 mutations / 15 RUN files; 135 tested, 4 untested, 3
  instrument-unroutable, 0 timeouts; elapsed 175.70s; verified score 95.07%.
- The three coverage-negative rows are the model `$hidden` declarations in
  `AuthCredential`, `AuthConnection`, and `AuthChallengeOutbox`; they are
  declaration-line instrumentation limits, but their secret/payload-redaction
  contracts still need ordinary serialization assertions. The four survivors
  are cast-map rows in `AuthChallenge`, `AuthCredential`, `AuthChallengeOutbox`,
  and `AuthAttempt`, requiring row-level review rather than being dismissed by
  the aggregate score.
- Artifacts: `artifacts/2026-08-24-models-66ac67d.log` (SHA-256
  `7c7c13033661913ac4be3ec625d15a9beb00e5a8518ba504ba750d34cd4cbbf8`) and
  `artifacts/2026-08-24-models-classification.json` (SHA-256
  `e58c45406a375259efdc9b54f0dbd2a7b5369878419b0dcf9baf42cfd3dfd581`).

### Queued mechanism ruling: console contracts

The 32 non-unroutable Console rows are one mechanism-level finding: command
output and exit-code contracts are not asserted. `VouchDoctorCommand` has 16
never-executed rows because every test uses `--json`, leaving its human output,
exit 0, and exit 2 paths untested. `VouchSmsIdentifierAuditCommand` has 16
executed-and-survived rows because both modes execute but tests assert only
that the exit code is zero; even the `--json` branch predicate can invert
without failing. Queue one focused ruling requiring output assertions per mode
and explicit assertions for all doctor exit codes. The six `CommandExit` enum
declaration rows remain instrument-unroutable and are not part of this ruling.

### Queued mechanism ruling: pessimistic row locks

The corrected classifier exposed one design question rather than a test-only
gap. Fifteen `DatabaseAuthThrottleStore` survivors collectively remove the
`FOR UPDATE` mechanism from every flagged read-modify-write path:

- Three default-parameter rows: `ipParent(..., bool $lock = false)` at line
  436, `counter(..., bool $lock = false)` at 742, and `lock(..., bool $lock =
  false)` at 839.
- Twelve `TrueToFalse` call-site rows passing `lock: true` (lines 108, 116,
  123, 174, 183, 198, 355, 359, 386, 390, 732, and 820).

`DatabaseDeliveryEconomics` contributes a fourth file to this same ruling.
Its `row()` lock guard (`:251`/`:252`) survives both condition negation and
removal of `lockForUpdate()`, and all three call-site `lock: true` arguments
(`:97`, `:178`, `:211`) survive switching off. Its constructor coalesce at
`:38` also repeats the injected-row-lock dependency gap seen in
EnrollmentGuard.

The full suite and all three engines preserve the throttle invariant with each
mutant. SQLite's grammar compiles `lockForUpdate()` to no SQL, so lock-removal,
lock-negation, and the affected `lock: true` call-site/default-parameter rows
are `engine-equivalent` under the measuring engine, not evidence that the
mechanism is redundant. The two unconditional sites produced no mutation rows;
their absence must not be read as kills. The source documents the workaround:
SQLite's `FOR UPDATE` is a bare `SELECT`, so the unique insert is intentionally
first to claim the writer lock before state-bearing reads. Keep this as one
mechanism-level ruling with stable row identities. Behavioural evidence on
MySQL/PostgreSQL may still validate the load-bearing paths, but it cannot move
the SQLite mutation rows.

The two SQLite driver-dispatch survivors at `DatabaseAuthThrottleStore:409`
and `:662` belong to this same mechanism ruling. `insertCounterIfMissing()` is
idempotent, so skipping an insert when the row already exists produces the
same state; the observable difference is whether SQLite claims its writer lock
before a state-bearing read. They require the same pre-existing-row,
two-writer contention harness. If that harness cannot deterministically expose
`SQLITE_BUSY` or a lost update under the mutant, classify these rows as
`concurrency-observable-only` rather than introducing a flaky value assertion.

EnrollmentGuard contributes three additional rows to this same ruling: the
two predicate-key removals at `EnrollmentGuard:126` (`user_id` and `type`) and
the wait-floor increment at `EnrollmentGuard:122`. They are lock identity and
bounded-wait mechanism rows, not a separate Enrollment finding. Its
constructor coalesce survivor at `EnrollmentGuard:50` is instead a dependency
injection test gap and remains separately classified.

### Queued mechanism ruling: Delivery reservation contract

At the initial Delivery ruling point, four DeliveryEconomics survivors formed
one contract-level finding. The
reservation short-circuit at `DatabaseDeliveryEconomics:88` has six surviving
mutants, including decoy and zero-cost branches; `:197` survives changing the
failed reservation claim's `continue` to `break`, which drops the tenant scope;
`:137` survives changing the release exactly-one-row invariant; and `:117`
survives removing the timestamp string cast from the cross-window release
guard. This was the historical queued set; subsequent artifacts show `:197`
was already killed by the seeded partial-replay test in the preceding batch.
These are one reservation mechanism—scope coverage, release safety,
and cross-engine window ownership—not four independent test requests. Keep
stable row identities and defer resolution to the test-design pass.

### Delivery equivalence classification

The Delivery survivor set is narrower than the raw 65-row count suggests.
Seventeen cast survivors are equivalent without a test gap:

- 13 are `redundant-cast`: `(string)` operands are typed string constants or
  string properties, and `(int) $ceiling` is guarded by `?int !== null`.
- 4 are `engine-equivalent`: SQLite returns native integers for the relevant
  reads, while MySQL/PostgreSQL may return strings. These remain open to
  cross-engine evidence, especially the reservation amount and window casts.

Four message-prose rows remain under the standing no-action ruling. The
then-actionable Delivery logic set was the short-circuit at `:88`, the
exactly-one-row release invariant at `:137`, the two-scope `continue` at `:197`,
and the reservation-key/country predicates at `:154` and `:57`; later batches
closed the predicates and the two-scope continuation.

`ConsumeChallenge:26` was reviewed and retracted from the correctness queue.
Its target prefix is observable only in the exception message under a
single-mutant run: removing `challenge:` cannot collide with either existing
`credential:` target because the other mutation is not applied simultaneously.
It therefore remains within the narrowed message-prose ruling. The
cross-type namespace observation is retained as design guidance for any future
mutation type, not as a test request.

The Jobs batch now has direct missing-row coverage for both `handle()` and
`failed()`, plus an exact one-second assertion on contention redispatch. The
missing-row `failed()` test currently ratifies the implementation's
`worker_failure` choice when `provider_attempted_at` cannot be read; it does
not settle whether that is the truthful attribution for a vanished row.

### Delivery refusal-batch confirmation (`6a86ad8`)

The second refusal-batch rerun used the same 229-mutation, 7-file scope and
the current SQLite coverage map at the test SHA. It produced 174 tested, 54
executed survivors, 1 never-executed row, and no timeouts. Against the prior
Delivery classification, eight identities were removed (killed): the country
predicate at `:57`, the decoy/zero-cost/empty-key release predicate at `:88`,
and the reservation-key guard at `:154`. The two-scope `continue` at `:197`
and the four `:137` comparison mutants remain survivors.

The `:137` survivors are equivalent for a stronger source-level reason than
cardinality. Both the failed-decrement branch and its fall-through execute
the same `released_at` update, and the update is the last statement in the
loop body; the conditional and its `continue` have no observable consequence.
`IncrementInteger` is also independently inert because the keyed update can
only report zero or one, but the other three mutants are equivalent because
the two arms are duplicated. This is an equivalent-by-duplicated-branch
finding with a queued source simplification, not a test request. The `:197`
survivor was already killed by the seeded partial-replay test in the preceding
Delivery batch; no additional test is required.

The redundant `:137` branch was then simplified in `06d0153`. The source
change removed seven generated mutations, as expected. The post-change rerun
produced 222 mutations / 7 RUN files, with 171 tested, 50 survivors, 1
uncovered, and 0 timeouts. Its expression-keyed baseline diff against the
pre-simplification classification reported exactly four removed rows (the
four former `:137` survivors) and no additions. Expression-keyed comparison
was required because the source edit shifted every later line; line-keyed
diffing would have produced spurious remove/add pairs.

The later console-output batch was measured against the refreshed union. The
Console scope remained 181 mutations / 8 RUN files (158 tested, 17 survivors,
6 uncovered); its row diff removed 28 survivor identities. Jobs remained 13
mutations / 1 RUN file (10 tested, 1 survivor, 2 uncovered); its row diff
removed two identities. Delivery remained 222 mutations / 7 RUN files (171
tested, 50 survivors, 1 uncovered), with no row movement: the SMS audit tests
route through Delivery but did not discriminate any Delivery survivor.

The subsequent SMS fixture batch strengthened `SmsIdentifierAuditTest` with
duplicate-country, out-of-order-country, canonical, and empty-country cases.
Its Delivery rerun retained the same 222 mutations / 7 RUN files and produced
176 tested, 45 survivors, 1 uncovered, and 0 timeouts. The expression-keyed
baseline diff removed exactly five identities and added none:
`SmsIdentifierAudit.php:27`, both `:41` rows, `:47`, and `:50`. This closes
those fixture gaps without changing mutation scope.

The Jobs missing-row test remains useful but does not kill
`DeliverOtpChallenge.php:46`. PHP 8's plain property read on `null` emits a
warning and yields `null`, so the nullsafe and plain forms both evaluate false
for `provider_attempted_at !== null` and record `worker_failure`. This is a
language-semantic equivalent mutant: the test ratifies current missing-row
attribution, while converting warnings to exceptions suite-wide is not
justified to kill one row.

### Cross-engine rollover evidence

`DeliveryEconomicsContentionTest` now includes a stale-window probe. A parent
transaction locks the global spend row, commits a concurrent rollover update,
and a child reservation must preserve that committed spend before adding its
own charge. The probe passes on file-backed SQLite and PostgreSQL (3 tests / 15
assertions on each engine). This is behavioral evidence for the load-bearing
rollover lock; it is intentionally not expected to move SQLite mutation rows,
because SQLite compiles `FOR UPDATE` to a bare `SELECT`.

The existing `ScalarThrottleContentionTest` is the shared throttle probe for
the pre-existing-row path: its two-writer issuance boundary reaches the
read/decide/write sequence and asserts exactly one permit at the threshold.
It passes on file-backed SQLite and PostgreSQL (3 tests / 12 assertions on
each engine). This covers the driver-dispatch setup as behavioral evidence;
the corresponding SQLite mutation rows remain engine-equivalent by design.

### Closing corpus aggregate

Using the latest classification artifact for each chunk at the current source
state, the corpus contains 526 classified rows:

| rows | executed-and-survived | never-executed | engine-gated | instrument-unroutable | timeout |
|---:|---:|---:|---:|---:|---:|
| 526 | 446 | 7 | 23 | 45 | 5 |

The 230 concatenation rows remaining in the corpus are covered by the narrowed
message-prose rule only where the operand is quoted English prose; labels,
prefixes, units, and data-bearing concatenations remain individually reviewed.
The reduction from the earlier 629-row aggregate is attributable to landed
tests and corrected dispositions, not omitted inventory.

Throttle is now 106 rows (91 survivors, 2 ruled never-executed, and all 10
engine-gated rows). Its lock and driver-dispatch
rows are intentionally supported by cross-engine behavioral evidence rather
than expected SQLite mutation-score movement.

Support was reclassified against the current three-engine union rather than
carried forward from the 2026-08-23 SQLite-era reading. Its 40 rows now split
into 25 executed-and-survived, 13 engine-gated, 1 never-executed
(`DatabaseTime.php:116`), and 1 timeout. The former 14-row never-executed gap
was therefore primarily engine coverage classification, not a new test queue.
The corrected corpus split was 46 never-executed and 23 engine-gated; the
thirteen-row movement was between those categories only. Subsequent
Notifications and root test batches closed the actionable portion of the
remaining gaps. The latest corpus split is 7 never-executed, all with an
explicit ruling, and no actionable never-executed gap remains.

### Final Notifications and root reruns

At source SHA `212212a` (test/evidence state `96bbe4a`), the Notifications and
root reruns reconciled to their assigned RUN files with zero added identities
and an empty disposition-change bucket. Notifications removed the final three
actionable terminal-cause rows; root removed the four middleware diagnostic
message rows. Both chunks now have zero actionable never-executed rows.

Artifacts: `artifacts/2026-08-26-notifications-final-96bbe4a.log`,
`artifacts/2026-08-26-notifications-final-classification.json`,
`artifacts/2026-08-26-root-final-96bbe4a.log`, and
`artifacts/2026-08-26-root-final-classification.json`, with the shared SQLite
map in `artifacts/2026-08-26-96bbe4a-sqlite.xml`.

The temporary `throttle-recovery-expiry` classification was discarded: its log
predated the `212212a` refactor, so line-keyed rows below the refactor could not
be attributed to the current source. The post-`212212a` artifact supersedes it.

### Narrowed concatenation dispositions

Inspection separates quoted English prose from concatenations that carry
behavioral data. The remaining non-prose sites are:

- `DatabaseAuthThrottleStore.php:514`, `:516`, and `:660`: unsigned relative
  time strings accepted by PHP's date parser; equivalent under language
  semantics and not test requests.
- `ThrottleReporter.php:99` and `:110`: date-boundary SQL predicates; these
  remain engine-sensitive review items rather than prose.
- `VouchDoctorCommand.php:80` and
  `VouchSmsIdentifierAuditCommand.php:43`: label-plus-value output; output
  assertions are required, so these do not belong to the prose no-action rule.

`ConsumeChallenge.php:26` remains message-only under a single-mutant run: its
`challenge:` prefix cannot collide with either existing `credential:` target
without applying a second mutation. `BoundedLockWait.php:112` is likewise not
prose; its PostgreSQL unit assertion is now present and its mutation evidence
remains cross-engine. The broad no-action rule applies only to concatenations
whose operands are explanatory quoted prose, not labels, prefixes, units,
dates, or data-bearing output.

The reporter date-boundary probe resolved the four `ThrottleReporter` rows
mechanically. `ConcatRemoveRight` at both `:99` and `:110` is
redundant-suffix equivalent: comparing against the date alone selects the same
rows because the day boundary is already implied. `ConcatRemoveLeft` and
`ConcatSwitchSides` at both sites are killable; the reservation fixture already
seeds a prior-day row and kills both mutations at `:110`, while the counter
fixture still needs one stale-window counter to discriminate the corresponding
`:99` rows. This is one queued fixture line, not a prose ruling.

The current Throttle run records one expected SQLite skip: the PostgreSQL-only
`SHOW lock_timeout` unit assertion for `BoundedLockWait:112`. That test cannot
execute on SQLite, so the suffix mutant will remain engine-equivalent in the
SQLite measurement despite the focused PostgreSQL proof. This is distinct from
the lock rows, whose tests execute but cannot distinguish `FOR UPDATE` after
SQLite compiles it away; both are engine-equivalent for different reasons.

### Adjudication join

The keyed manifest at `docs/superpowers/mutation/rulings.json` contains 154
stable expression-identity entries covering 258 of the 526 classified rows.
After excluding the 45 instrument-unroutable and 23 engine-gated rows closed
by measurement, 200 executed-and-survived rows remain unadjudicated. Run the
classifier with `--rulings=docs/superpowers/mutation/rulings.json` to join
adjudications and surface `ruling_mismatch` when a later measurement disagrees
with a recorded ruling. The manifest is pinned to source SHA `212212a`;
source edits require revalidation of expression identities.

### Full parallel smoke (non-authoritative)

- Scope: non-Kernel `Fissible\\Vouch`, SHA `66ac67d`, 10 processes
- Result: 3,155 mutations / 91 files; 2,545 tested, 439 untested, 118
  uncovered, 53 timeouts. The displayed 82.35% credits timeouts; verified
  kills alone are 2,545 / 3,155 = 80.66%.
- This run proves the patched harness completed without fatals or “No tests
  found”; it does not provide file membership or timeout identities and cannot
  close any chunk.

## Completion condition

Reconciliation is complete only after every assigned mutant-bearing file has a
non-compact `RUN` membership, every emitted row has a stable disposition, all
timeouts are separately resolved, and queued tests have been applied. The
closing confirmation is a sequence of non-compact, path-scoped chunk runs at
one explicitly recorded post-test SHA; a parallel compact invocation is
smoke-only because it cannot provide the `RUN` headings and row identities the
ledger requires. Before that sequence, regenerate the three-engine coverage
union at the same SHA and compare it with the preceding union. Re-measure every
chunk whose covered-line set changed; retain an explicit, evidence-backed
exclusion record for unchanged chunks. The final chunk artifacts and union
must together confirm the resulting ledger.
