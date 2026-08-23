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

## Measurement rules

- Record the exact SHA (`66ac67d`) and the plugin timeout threshold in every
  chunk artifact.
- Report verified kills separately from untested, uncovered, and timeout rows.
  A timeout is unresolved until rerun under the recorded conditions.
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
| Delivery | `src/Delivery/` | 14 | 137.63s / 37.69s | measured: 229 mutations / 7 RUN files; 164 tested, 64 untested, 1 uncovered, 0 timeouts |
| Flow | `src/Flow/` | 10 | AuthFlow 239.82s / 36.82s | partial: `AuthFlow.php` measured (285 mutations; 272 tested, 12 untested, 1 uncovered); 9 files pending |
| Throttle | `src/Throttle/` | 13 assigned / 7 mutant-bearing | 3,047.11s / 38.52s | rerun measured: 865 mutations; 739 tested, 86 untested, 40 uncovered, 0 timeouts; verified score 85.43% |
| Kernel | `src/Kernel/` | 26 | pending | pending; disclosure-sensitive (`ErrorShaper`, `ScreenSpec`, `RetryPolicy`) |
| Console | `src/Console/` | 8 | pending | pending |
| Notifications | `src/Notifications/` | 9 | pending | pending |
| Core / data and boundaries | explicit sub-runs below | 82 | pending | pending; no aggregate run may stand in for its sub-runs |

Core sub-runs are deliberately itemized because routing breadth makes one
82-file estimate misleading:

| sub-run | source files | status |
|---|---:|---|
| Attempts | 10 | pending |
| Contracts | 9 | pending |
| Enrollment | 3 | pending |
| Factors | 16 | pending |
| Http | 7 | pending |
| Jobs | 1 | pending |
| Models | 15 | pending; expected high routing breadth |
| Persistence | 3 | pending |
| Recovery | 2 | pending |
| Secrets | 2 | pending |
| Sessions | 5 | pending |
| Support | 6 | pending |
| Tenancy | 1 | pending |
| root (`Vouch.php`, `VouchServiceProvider.php`) | 2 | pending |

The assignment covers all 162 source files and therefore cannot silently omit
the nine remaining Flow files. The **91-file figure is provisional**: the
authoritative subset will be the intersection of this inventory with the
`RUN` lists emitted by the seven non-compact chunk measurements, and the ledger
must replace the provisional total with that sum before reconciliation can
close. Zero-mutant files are retained here as explicit zero-mutant evidence
rather than disappearing from the ledger.

## Valid measurements

### Delivery

- Command scope: `Fissible\\Vouch\\Delivery`
- SHA: `66ac67d`
- Baseline: 1,161 tests, file-backed SQLite, 31.41s
- Timeout threshold: 37.69s (baseline + `max(5s, 20%)`)
- Result: 229 mutations / 7 files; 164 tested, 64 untested, 1 uncovered,
  0 timeouts; verified score 71.62%

### Flow / AuthFlow

- Command scope: `Fissible\\Vouch\\Flow\\AuthFlow`
- SHA: `66ac67d`
- Baseline: 1,161 tests, file-backed SQLite, 30.68s
- Timeout threshold: 36.82s
- Result: 285 mutations / 1 file; 272 tested, 12 untested, 1 uncovered,
  0 timeouts; verified score 95.44%
- This does **not** close Flow. `VerificationEqualizer`, `ScreenBuilder`, and
  the seven remaining result/request classes require their own RUN evidence.

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

### Queued mechanism ruling: throttle row locks

The corrected classifier exposed one design question rather than a test-only
gap. Fifteen `DatabaseAuthThrottleStore` survivors collectively remove the
`FOR UPDATE` mechanism from every flagged read-modify-write path:

- Three default-parameter rows: `ipParent(..., bool $lock = false)` at line
  436, `counter(..., bool $lock = false)` at 742, and `lock(..., bool $lock =
  false)` at 839.
- Twelve `TrueToFalse` call-site rows passing `lock: true` (lines 108, 116,
  123, 174, 183, 198, 355, 359, 386, 390, 732, and 820).

The full suite and all three engines preserve the throttle invariant with each
mutant, while the two unconditional `lockForUpdate()` sites are killed. This
does not yet establish whether the flagged locks are redundant under the
constructed races (unique inserts may be carrying the invariant), or whether
the tests fail to discriminate the pessimistic mechanism. Keep this as one
mechanism-level ruling with stable row identities; do not add tests or remove
locks during the measurement sequence. Resolution options remain: a
mechanism-specific concurrency proof, a deliberately narrow SQL assertion, or
removal if the unique-constraint design is shown sufficient.

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
timeouts are separately resolved, queued tests have been applied, and a final
full run at the post-test SHA confirms the resulting ledger.
