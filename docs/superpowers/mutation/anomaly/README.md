# RESOLVED — the 56 provider rows were a PCRE limit, not survivors

**Root cause identified 2026-08-15.** 42 of the 56 were instrument artifacts and
are killed. 14 are genuine survivors and still need rulings.

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

Re-run with the overflow bypassed (whole suite per mutant, `--bail`; the
unmutated suite is green, so any failure is attributable to the mutation, and a
superset of the covering tests can only agree with a kill, never invent one):

| | before | after |
|---|---|---|
| tested (killed) | 7 | **49** |
| untested | 56 | **14** |
| uncovered | 6 | 6 |
| children reporting "No tests found" | 56 | **0** |

## Blast radius — one file

Computed from the real full-suite coverage map by replaying the plugin's own
filter construction, at the **whole-file union**, which is the absolute upper
bound on any single mutation's filter:

**1 of 90 covered source files can overflow.** Only `VouchServiceProvider.php`
(453 tests, 37,818 bytes). The next largest is
`Models/Concerns/EnforcesValueBounds.php` at 227 tests / 19,263 bytes — a 1.8×
margin under the ceiling. The rest of the 1314-mutation baseline is unaffected,
and only the provider's rows need re-measuring.

## The 14 genuine survivors

Real work, still open. All in `src/VouchServiceProvider.php`:

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

The anomaly reproduces at **file scope** — no 814s full run needed:

```bash
vendor/bin/pest --mutate --path=src/VouchServiceProvider.php
# 149s, and reports exactly 56 untested / 6 uncovered / 7 tested
```

The corrected numbers were produced by temporarily patching
`vendor/pestphp/pest-plugin-mutate/src/MutationTest.php` to drop the filter when
`strlen($joined) > 30000` and run the whole suite instead. **That patch is a
measurement instrument and has been reverted; vendor/ is pristine.** Any future
run reproducing these numbers must re-apply it, or the upstream fix must land.

## What this means for the gate

Blocker 2 is no longer "unexplained". It is a known tool defect with a known
threshold affecting exactly one file, and the affected rows now have real
verdicts. What remains before Task 13 can close:

1. Rule the 14 genuine survivors above.
2. Regenerate the authoritative manifest. Its IDs may be stable, but no current
   test outcome is attested by the pre-matrix run — and the provider's rows in
   particular were measured by a broken instrument.
3. Decide the durable control for the provider. Options: carry the vendor patch
   deliberately (composer patch), report upstream (`@preg_match` swallowing a
   compile failure is the reportable defect, chunking the filter is the fix), or
   accept whole-suite measurement for this one file. Whichever is chosen must be
   written down, because a future run on an unpatched plugin will silently
   report 56 survivors again.
