# Authoritative reconciliation — composition, not count

Run: `pest --mutate --class="Fissible\Vouch" --ignore="Kernel"`, 814s.
Zero fatals. 1314 mutations for 60 files; 60 files in the `RUN` list; **0 kernel
files**. Score 72.30% → **75.88%**. Survivors 364 → 317.

**Mutation IDs are directly comparable**: zero source commits between the two
runs, so every kill came from a test rather than a source edit.

| Check | Result |
|---|---|
| IDs gone since the manifest | **47** |
| New IDs not in the manifest | **0** |

47 kills, spread exactly across the files this session's tests targeted —
`Vouch.php` 10, `ScreenBuilder` 5, `AuthLinkRequest` 3, `GraceGuard` 2,
`FactorRegistry` 2, `DatabaseAttemptStore` 2, `PasswordFactor` 2,
`GuardsChallengeTarget` 1, `AssuranceComparator` 1, `VouchPruneCommand` 1, and
the model cast rows.

## The composition mismatch — and what it actually is

I recorded 56 of `VouchServiceProvider`'s 62 rows as killed. **All 62 still
survive.** The count would have hidden this; the composition did not.

The rows report `UNTESTED`, not `UNCOVERED` — Pest ran a covering set and nothing
failed. But the tests plainly do detect these mutations:

> Breaking the routes path and running the whole suite: **530 failed, 157
> passed.**

Both facts are true because **mutation testing runs only the tests coverage
attributes to the mutated line**, and a service provider's `boot()`/`register()`
execute during application bootstrap — before any test body, and outside the
per-test coverage attribution pcov records. The covering set for those lines is
therefore not the set that exercises them.

### A third category: TOOL-BLIND

Distinct from the two already recorded, and it must not be confused with either:

- **not equivalent** — the mutations change real behaviour;
- **not a test gap** — the behaviour is asserted, and removing the assertion's
  target fails 530 tests;
- **the framework structurally cannot observe the kill**, because of when the
  code runs relative to coverage attribution.

Calling these "killed" in the manifest would be false: the tool did not observe
it. Calling them "surviving" would be equally false: the code is covered by
probed, load-bearing assertions. They are recorded as **tool-blind, with the
evidence attached** — `ProviderEffectTest`, plus the per-expression probes that
failed 11–19 tests each.

## Remaining unresolved

| Category | Rows | Status |
|---|---|---|
| Tool-blind (provider bootstrap) | 56 | Evidence recorded; not observable by mutation testing |
| Matrix-required | 4 | Blocked on Task 14's MySQL/Postgres probes |
| Prose, equivalent, compensating control | the balance | Ruled, premises recorded and tested |

Task 13 remains **blocked on Task 14** for the four matrix-required rows, and now
additionally carries the tool-blind category as a documented limitation of the
instrument rather than a gap in the suite.
