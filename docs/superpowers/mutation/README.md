# Phase 2.3 mutation gate — start here

**Status: Task 13 OPEN. Branch `feat/vouch-2-3-flow-http` must not merge.**

Both original blockers are resolved — blocker 1 (the four matrix rows) and
blocker 2 (the provider rows, a confirmed `pest-plugin-mutate` defect). The
manifest has been regenerated on a patched install
(`2026-08-15-survivor-manifest.md`) and two of its three closure checks pass:
the provider reports 0 untested, and no new mutation escaped.

**The third does not: 63 of 261 surviving rows are not yet joined to a ruling.**
They sit in files no exhaustive ruling document covers — `DatabaseTime` (15) has
no candidate document at all. That is what Task 13 now waits on.

**Run the gate only on a patched install.** `composer install` applies
`patches/pest-plugin-mutate-3.0.5-chunk-filters.patch`; without it the provider
silently reports 56 phantom survivors, because a child that runs zero tests exits
0 and is scored as survival. `tests/Mutation/FilterChunkingTest.php` fails if the
patch is not declared.

## The gate (revised — there is no score floor)

A floor was the original plan and was withdrawn on evidence this audit produced:
`Support` measures 0.00% and is well tested, while `Persistence` measured 0.00%
and had 39 genuinely untested mutants. A percentage cannot tell those apart, so a
floor rewards mutator-friendly code shape rather than test quality.

The enforceable control is in `2026-08-13-phase2-survivor-audit.md` under
*The gate*. Summarised: full-scope run; source-to-`RUN` reconciliation with
per-file zero-mutation evidence; every survivor, timeout and uncovered mutation
killed or dispositioned, with its premise tested where the ruling rests on one;
and no new undispositioned mutation. **The score is a diagnostic only.**

## Running it

```bash
vendor/bin/pest --mutate --class="Fissible\Vouch" --ignore="Kernel"
```

Two traps, both of which produced false results before being found:

- **`--ignore` takes a PATH fragment, not a namespace.** `"Fissible\Vouch\Kernel"`
  matched nothing, so every baseline before `2026-08-15` silently *included* the
  kernel.
- **The runner exits 0 when it truncates.** Check `Fatal error` count is zero and
  that "N Mutations for M Files" matches the number of distinct `RUN` lines. An
  early attempt covered 12 of 73 files and reported success.

`tests/bootstrap.php` raises the memory limit for mutation runs only, via
`MutationRun::isActive()`. `phpunit.xml.dist`'s 128M pin must stay — the
eager-solver guard only fails, rather than hangs, at that limit.

## Last authoritative run

2026-08-15, on a patched install: 0 fatals · 1314 mutations · 60 files · 60 `RUN`
· 0 kernel · 0 "No tests found" · 899s · **80.14%**. 239 untested · 22 uncovered ·
4 timeout · 1049 tested. Enumerated row by row in
`2026-08-15-survivor-manifest.md`.

Reconciled: 83 files in scope = 60 mutated + 23 zero-mutation, each evidenced per
file in `2026-08-13-namespace-checklist.md`.

A row is discharged only by a document that rules its file-set **exhaustively**
("N of N ruled"). A document that merely mentions a file does not rule its rows —
the slices over-include and do not partition, so membership is not
correspondence.

## Blockers

**1. Matrix-required (4 rows) — CLOSED 2026-08-15.** Run on MySQL 8 and
Postgres 16; see `2026-08-15-matrix-rulings.md`. Three rows were misclassified
and are `equivalent` on every engine — the premise that MySQL and Postgres
return numeric strings for integer columns is false on PHP 8.4, and is now
pinned by a test so the ruling fails loudly if a driver ever changes.
`EnrollmentGuard:97` was real and is **killed** on Postgres by a new
re-enrollment contention test; it had survived because every existing contention
test exercised only the first-enrollment path, where the insert serializes and
the lock call is redundant.

**2. The 56 provider rows — CLOSED 2026-08-15. A confirmed upstream defect.**
See `upstream-defect/`. PCRE cannot compile the plugin's 453-alternation,
37,818-byte `--filter`, and PHPUnit's `@preg_match(...) === 1` turns that compile
failure into "no test matches". The child runs zero tests, exits 0, and the
plugin scores survival. Threshold bisected at 409 alternations / 34,140 bytes.
Exactly **1 of 90** covered files can overflow, so the rest of the baseline was
never affected.

42 rows were artifacts; the 14 genuine survivors are killed. The provider now
reports **0 untested, 63 tested, 6 uncovered (dispositioned prose), 91.30%**.

The durable control is a version-pinned Composer patch that chunks the derived
filters, applied by `composer install` and guarded by
`tests/Mutation/FilterChunkingTest.php` — see `2026-08-15-durable-control.md`.
Whole-suite-per-mutant was the diagnostic, NOT the control: an unrelated flaky
failure would falsely credit a kill, where chunked filters keep the tool's
intended causal signal.

## Disposition classes

`equivalent` · `schema-conditional` (equivalent only while a separately tested
premise holds) · `compensating control` (overlapping today, redundancy retained
as deliberate margin). Per-file rulings are in the dated `*-rulings.md` files.

## Standing rules earned the hard way

- Classify a concatenation by **dataflow**, never by mutator family. Three
  concatenations in this codebase were protocol values, not prose.
- When asserting that code *chose* a value, assert on the artifact that
  distinguishes choices — never membership of a list containing all candidates.
- Assert exception **messages**, not just classes, when the class is as broad as
  `RuntimeException`.
- Test the primary mechanism's own artifact, not only the behaviour its layers
  jointly produce.
- The survivor count is an **upper bound** on real survivors, not a measurement.
- A claim about what a **driver** returns is an empirical claim. Three rows were
  sent to the matrix on "MySQL and Postgres return numeric strings", which one
  `PDO` probe disproves. Probe the driver before classifying on its behaviour,
  and when a ruling rests on driver behaviour, pin it with a test.
- **A tool that reports success can be reporting nothing at all.** The provider's
  56 "survivors" were a child process running zero tests and exiting 0. When a
  runner's verdict rests on an exit code, confirm work actually happened — count
  the tests it claims to have run.
- **A ruling document discharges a row only if it rules its file-set
  exhaustively.** Joining the manifest by "which document mentions this file"
  over-credits badly: it counted `Vouch.php` as ruled by a reconciliation record
  that only listed how many of its IDs had disappeared. Require an "N of N
  ruled" claim, and treat a subset of an exhaustively ruled set as ruled only
  once you have checked the file gained no rows.
- **Namespace-organised passes leave whole directories unruled.** `Secrets`,
  `Notifications` and `Support/DatabaseTime` were enumerated in the manifest and
  never ruled, because every file-by-file pass was scoped to namespaces that did
  not include them. Reconcile the manifest against the rulings, not the rulings
  against themselves.
- When a guard has two paths, ask which one the tests take. Four contention
  tests all entered `EnrollmentGuard::acquire()` with no lock row, where the
  insert serializes — so none of them could see `lockForUpdate` disappear, and
  the path they missed is the one production is almost always on.
