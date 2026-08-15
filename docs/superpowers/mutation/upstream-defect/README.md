# RESOLVED — the 56 provider rows were a PCRE limit, not survivors

**Confirmed upstream defect, root cause identified 2026-08-15.** 42 of the 56
were instrument artifacts. The other 14 were genuine survivors and are now
killed. The provider reports **0 untested**.

The durable control is a version-pinned Composer patch that chunks the derived
filters — see `../2026-08-15-durable-control.md`. The report for upstream is
`UPSTREAM-REPORT.md` beside this file. Task 13 does not wait on upstream.

The instrument was not "untrustworthy" in some diffuse way. It fails in one
precise, reproducible place, for one file, above a measurable threshold.

## The chain

1. For each mutation the plugin builds a single `--filter` regex alternating
   **every test that covers the mutated lines** (`MutationTest.php:52-62`).
   `src/VouchServiceProvider.php` is touched by **453 tests** — every test that
   boots the package — giving a **37,818-byte** pattern.
2. PCRE2 refuses to compile it:
   `preg_match(): Compilation failed: regular expression is too large at offset 0`.
3. `NameFilterIterator.php:66` is `@preg_match($this->regularExpression, $name) === 1`.
   The `@` suppresses the warning and `false === 1` is indistinguishable from
   "this test does not match", so **every** test is filtered out.
4. The child prints `INFO No tests found.` and **exits 0**.
5. `MutationTest::hasFinished()` reads `isSuccessful()` as survival →
   `MutationTestResult::Untested`.

A green suite and a silently-empty suite produce the same exit code. That is the
whole bug.

## The threshold, bisected

| alternations | bytes | `preg_match` |
|---|---|---|
| 409 | 34,140 | compiles |
| 410 | 34,222 | `false` — "regular expression is too large" |

Not the JIT: identical failure at `pcre.jit=0`. Not the capture groups:
`(?:.*)` and bare `.*` both still fail. Not tunable from `php.ini` — it is a
PCRE2 compiled-size limit. PHP 8.4.24, PCRE2 10.47.

The literal `"` quoting in `--filter="…"` is **benign** and was correctly cleared
by the earlier investigation: PCRE accepts `"` as a delimiter, so the plugin's
argument is a valid delimited regex until it gets too big.

## Why the earlier evidence all checked out

The seven verified layers — attribution, derivation, selection, discrimination,
quote form, inherited options, mutation-file interception — were all **correct**,
and all downstream of the break. The filter was right at every layer. It was
simply too large to compile, and the one component that noticed threw the
information away.

The manual reproduction killed the mutation because a hand-run child uses a
*subset* of the filter, small enough to compile.

## Corrected verdicts

Two measurements, in order. The first diagnosed the defect by bypassing the
overflow (whole suite per mutant under `--bail`); it is **corroboration only**,
not the control, because an unrelated flaky failure would falsely credit a kill.
The second is the real instrument: the chunked filters the durable patch
installs, which keep the tool's causal signal — each mutation is still judged by
the tests that actually cover it.

| | original | whole-suite (diagnostic) | chunked patch (authoritative) |
|---|---|---|---|
| tested (killed) | 7 | 49 | **63** |
| untested | 56 | 14 | **0** |
| uncovered | 6 | 6 | 6 |
| "No tests found" children | 56 | 0 | **0** |
| score | 10.14% | — | **91.30%** |
| duration | 149s | 302s | 110s |

The 14 that survived the diagnostic run were genuine, and are killed by the
tests described below. The 6 uncovered rows are line 246's `RuntimeException`
message, already dispositioned PROSE by dataflow in
`../2026-08-14-provider-rulings.md`.

## Blast radius — one file

Computed from the real full-suite coverage map by replaying the plugin's own
filter construction, at the **whole-file union**, which is the absolute upper
bound on any single mutation's filter:

**1 of 90 covered source files can overflow.** Only `VouchServiceProvider.php`
(453 tests, 37,818 bytes). The next largest is
`Models/Concerns/EnforcesValueBounds.php` at 227 tests / 19,263 bytes — a 1.8×
margin under the ceiling. The rest of the 1314-mutation baseline is unaffected,
and only the provider's rows need re-measuring.

## The 14 genuine survivors — all killed

Two weak assertions, both instances of standing rules this audit already wrote
down.

**Eight `singleton()` removals (lines 52, 62, 91, 99, 123, 150, 183, 195).**
`ContainerWiringTest`'s `it('resolves every singleton the provider registers as
one shared instance')` named **three** of the provider's sixteen singletons while
its name promised all of them. The three it named were killed; the eight nothing
else covered survived. Dropping one leaves a class that still resolves — Laravel
autowires most of them — but hands a fresh instance to every caller, so state
registered once per request silently becomes per-resolution state. The dataset is
now an exact enumeration. `FlowResultHandler` needs a `StatefulGuard` the test
application does not bind, so it has its own test rather than being quietly
dropped: a singleton missing from an exhaustive list is the exact defect that
test exists to catch.

**Six publish rows (lines 253, 254, 257, 258).** `ProviderEffectTest` asserted
only that the source list was non-empty and that every entry existed on disk.
Both halves were blind:

- Non-empty survives deleting either `publishes()` call outright, because the
  other keeps the list non-empty — *never assert membership of a list containing
  all the candidates*.
- `file_exists()` survives truncating `__DIR__ . '/../config/vouch.php'` to
  `__DIR__`, because a directory exists as happily as the file inside it. An
  assertion that cannot tell a path from its own parent cannot tell a correct
  path from a wrong one. This is the *classify concatenation by dataflow* rule:
  these are filesystem paths, not prose.

Now asserted per tag as exact source-to-target pairs, with sources normalised
through `realpath` because the provider builds them by concatenation and they
arrive unresolved.

The rows, for the record:

| line | mutator | id |
|---|---|---|
| 52 | RemoveMethodCall | `07b86c49cc57d39f` |
| 62 | RemoveMethodCall | `a41011d6fe724ebc` |
| 91 | RemoveMethodCall | `e984c88a05ffaf58` |
| 99 | RemoveMethodCall | `ebc7bfbe0581785d` |
| 123 | RemoveMethodCall | `969f0fed53390a69` |
| 150 | RemoveMethodCall | `611dd48accf0812f` |
| 183 | RemoveMethodCall | `91f0001d0c681155` |
| 195 | RemoveMethodCall | `32de5a5276d84133` |
| 253 | RemoveMethodCall | `6e2ab2a9f39eb425` |
| 254 | RemoveArrayItem | `85ce55a65ed03091` |
| 254 | ConcatRemoveRight | `8e260cf04ea59b92` |
| 257 | RemoveMethodCall | `9643aad25acc8700` |
| 258 | RemoveArrayItem | `0b4016f65c55d3b4` |
| 258 | ConcatRemoveRight | `ca1f2fa99c507c58` |

Per the standing rule, classify the two `ConcatRemoveRight` rows by **dataflow**
rather than mutator family before assuming they are prose.

## Reproducing

The defect reproduces at **file scope** — no 814s full run needed:

```bash
vendor/bin/pest --mutate --path=src/VouchServiceProvider.php
# 149s, and reports exactly 56 untested / 6 uncovered / 7 tested
```

To reproduce the **original** broken numbers you must uninstall the patch; a
patched install now reports 0 untested. The diagnostic whole-suite measurement
used a throwaway edit to `MutationTest.php` that dropped the filter above 30,000
bytes; that edit is gone and the durable patch replaced it.

## What this means for the gate

Blocker 2 is closed as a cause. It was a known tool defect with a known threshold
affecting exactly one file; the rows have real verdicts and the instrument is
fixed under a version-pinned Composer patch
(`../2026-08-15-durable-control.md`), so a clean `composer install` cannot
silently restore the broken measurement.

Remaining for Task 13: the regenerated authoritative manifest, produced with the
patch in place.
