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
- A chunk command must assert a positive mutation count and reconcile its `RUN`
  count to the assigned mutant-bearing files. `--min=0` otherwise permits a
  misspelled scope to exit successfully with `0 Mutations for 0 Files`.
- Record the literal command line, not a Markdown-escaped namespace spelling.
  For nested namespaces, prefer the directory-literal `--path=src/Kernel`
  filter; the class filter matches only an exact namespace declaration.

## Chunk assignment

| chunk | assigned source directories | source files | elapsed / timeout | status at `66ac67d` |
|---|---|---:|---|---|
| Delivery | `src/Delivery/` | 14 | 137.63s / 37.69s | measured: 229 mutations / 7 RUN files; 164 tested, 64 untested, 1 uncovered, 0 timeouts |
| Flow | `src/Flow/` | 10 | AuthFlow 239.82s / 36.82s | partial: `AuthFlow.php` measured (285 mutations; 272 tested, 12 untested, 1 uncovered); 9 files pending |
| Throttle | `src/Throttle/` | 13 | 3,165.85s / 37.28s | measured: 865 mutations; 736 tested, 89 untested, 40 uncovered, 0 timeouts; verified score 85.09% |
| Kernel | `src/Kernel/` | 26 | pending | pending; disclosure-sensitive (`ErrorShaper`, `ScreenSpec`, `RetryPolicy`) |
| Console | `src/Console/` | 8 | pending | pending |
| Notifications | `src/Notifications/` | 9 | pending | pending |
| Core / data and boundaries | explicit sub-runs below | 82 | pending | pending; no aggregate run may stand in for its sub-runs |

Core sub-runs are deliberately itemized because routing breadth makes one
83-file estimate misleading:

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
- Result: 865 mutations / 13 source files; 736 tested, 89 untested, 40
  uncovered, 0 timeouts; verified score 85.09%
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
  mutations because nested namespaces are not matched by that exact-class
  filter. It exited successfully under `--min=0` and is explicitly discarded;
  the path-scoped run is the authoritative Kernel measurement.
- Coverage routing identifies 25 of the 26 uncovered rows as
  **instrument-unroutable** declaration/match lines (14 `TransitionRules`
  constant declarations, 10 `FactorStrength` enum-case declarations, and the
  `SatisfiabilityEvaluator` match line). The remaining uncovered row is the
  genuine `ErrorShaper::strictLockRetry()` disclosure gap; queue a focused test
  for it, but do not land it during measurement.
- The five untested rows are on executed lines and remain genuine survivor
  candidates for individual classification.

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
