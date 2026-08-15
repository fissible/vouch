# Phase 2.3 mutation gate — start here

**Status: Task 13 BLOCKED. Branch `feat/vouch-2-3-flow-http` must not merge.**

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

0 fatals · 1314 mutations · 60 files · 60 `RUN` · 0 kernel · 814s · 75.88%.
Reconciled: 83 files in scope = 60 mutated + 23 zero-mutation, each evidenced per
file in `2026-08-13-namespace-checklist.md`.

## Two independent blockers

**1. Matrix-required (4 rows) — Task 14, MySQL and PostgreSQL only.**
`AuthAttempt:42` version cast (CAS), `AuthChallenge:39` attempts counter,
`AuthCredential:57` last_used_timestep (TOTP replay guard), `EnrollmentGuard:97`
`lockForUpdate`. SQLite cannot decide any of them. Proof for each: assert the
typed behaviour on both engines, remove the cast or call, confirm the
engine-specific test fails. See `2026-08-15-cast-classification.md`.

**2. Unexplained mutation-run discrepancy (56 provider rows).**
See `anomaly/`. A faithfully reproduced child kills these mutations; the
aggregate run reports `UNTESTED`. Seven layers verified correct. They are neither
killed nor dispositioned. Independent of blocker 1 — do not sequence Task 14
behind it.

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
