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

### Direct invocation was tried before concluding

"Not attributed during Testbench bootstrap" is a weaker claim than "impossible to
attribute", and the difference was tested rather than argued.

`tests/Database/ProviderAttributionProbeTest.php` instantiates
`new VouchServiceProvider(app())` and invokes `boot()` **inside a test body**,
after emptying the router's route collection so the assertion cannot pass on
routes the real bootstrap already registered. It is discriminating: with the
routes path broken, running that file directly gives **1 failed**.

The mutation run still reports those rows `UNTESTED`. So a test that executes the
line, inside its own body, and demonstrably fails when the line is broken, is
still not selected as a covering test for it.

That rules out the bootstrap-timing explanation as the whole story: moving the
invocation into a test body does not make the mutation observable. What remains
unproven is whether some other arrangement could — so this is recorded as *not
achieved by direct invocation*, not as *provably impossible*.

### The failed layer, identified

The plugin builds its child command as
`'--filter="'.implode('|', $filters).'"'`
(`pest-plugin-mutate/src/MutationTest.php:89`), where the filters derive from
`$codeCoverage->getData()->lineCoverage()`
(`Tester/MutationTestRunner.php:116`).

Dumping that exact structure for `src/VouchServiceProvider.php` settles which
layer fails:

```
line 31   1 test(s): P\Tests\Database\ProviderAttributionProbeTest::__pest_evaluable_it_registers…
line 226  1 test(s): …same…
line 227  1 test(s): …same…
line 230  1 test(s): …same…
```

**Coverage attribution works.** The provider's `boot()` lines map to the
direct-invocation test by name, in the very structure the plugin consumes. So
this is *not* coverage-attribution blindness — the first branch of the diagnostic
is eliminated.

The mutation nonetheless reports `UNTESTED`, so the failure is downstream of
attribution: in filter selection or in the child invocation built from it. Two
candidates remain, and which one has not been established:

- the generated `--filter` argument embeds literal `"` characters, since the
  quotes are inside a single argv element passed through Symfony Process rather
  than a shell; and
- Pest's `__pest_evaluable_…` test identifiers contain characters that must
  survive being joined with `|` into one regex.

Either would select an empty or non-matching test set, which the plugin then
reports as a surviving mutation rather than as a selection failure — the same
silent-success shape as the exit-0 truncation earlier in this audit.

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
evidence attached** — `ProviderEffectTest`, the per-expression probes that failed
11–19 tests each, the whole-suite probe at 530 failures, and the direct-invocation
attempt above.

The category is held open rather than closed, and is now narrower still: the
instrument's coverage attribution is CORRECT, and the failure lies in how it
turns that attribution into a child test run. That is a defect in the harness,
not a property of the code or of the tests.

## Remaining unresolved

| Category | Rows | Status |
|---|---|---|
| Tool-blind (provider bootstrap) | 56 | Evidence recorded; not observable by mutation testing |
| Matrix-required | 4 | Blocked on Task 14's MySQL/Postgres probes |
| Prose, equivalent, compensating control | the balance | Ruled, premises recorded and tested |

Task 13 remains **blocked on Task 14** for the four matrix-required rows, and now
additionally carries the tool-blind category as a documented limitation of the
instrument rather than a gap in the suite.
