# The durable control for the pest-plugin-mutate filter defect

**This is a confirmed upstream defect, not an anomaly.** The provisional category
is retired; `upstream-defect/` holds the record and `UPSTREAM-REPORT.md` in that
directory is the self-contained report.

## What is installed

A version-pinned Composer patch. `composer install` applies it; nothing depends
on remembering to do anything by hand.

```json
"require-dev": { "pestphp/pest-plugin-mutate": "3.0.5" },
"extra": {
  "patches": {
    "pestphp/pest-plugin-mutate": {
      "Chunk derived test filters below PCRE compile limit (upstream defect)":
        "patches/pest-plugin-mutate-3.0.5-chunk-filters.patch"
    }
  },
  "composer-exit-on-patch-failure": true
}
```

Three deliberate choices:

- **The version is pinned exactly.** A patch is written against one version's
  source. A bumped plugin with a stale patch must fail the install loudly rather
  than apply fuzzily or silently skip.
- **`composer-exit-on-patch-failure` is true.** A patch that fails to apply must
  break the build, not print a warning that scrolls past. The failure mode being
  guarded against is silent, so the guard cannot be silent.
- **The plugin was promoted from a transitive dependency to an explicit
  dev requirement**, because you cannot pin or patch what you do not declare.

## What the patch does

Splits the derived covering-test filters into chunks that PCRE can compile, and
requires **every** chunk to pass before a mutation is recorded as survived — the
first chunk that fails has killed it.

This preserves the tool's intended causal signal: a mutation is still judged by
the tests that actually cover it, not by the suite at large. Whole-suite-per-mutant
was used to *diagnose* the defect and is kept only as corroboration; it is not the
control, because an unrelated flaky failure would falsely credit a kill.

Two details that matter:

- Each chunk is verified by **actually compiling it**, and anything that still
  fails is halved recursively. The limit applies to the compiled pattern, not to
  source bytes, so the 16,000-byte budget is a starting point rather than a
  guarantee.
- A filter that already compiles yields exactly **one** chunk, so the other 89
  covered files behave precisely as upstream does.

## The four things the gate proves

All four are executable. The first, second and fourth run in `composer test`
(`tests/Mutation/FilterChunkingTest.php`); the third is a mutation run.

| # | Claim | Where |
|---|---|---|
| 1 | The 453-test provider set splits into compilable child filters | `it('splits the 453-test provider set into chunks PCRE can compile')` — 3 chunks of 192 / 190 / 71, each compiling |
| 2 | The original oversized pattern still fails on an unpatched install | `it('reproduces the upstream defect: the unchunked provider filter will not compile')` — asserts `preg_match` returns `false` with `PREG_INTERNAL_ERROR` |
| 3 | The representative provider mutation is reported Tested, not Untested | the scoped mutation run below |
| 4 | The expected direct provider probe is among the failing evidence | `ProviderAttributionProbeTest` fails against the committed mutant and passes against real source; it sits in chunk 0, which compiles |

Two further properties are pinned because getting them wrong would reintroduce
the same class of silent failure:

- **Chunking partitions, it does not sample.** A dropped filter is a test that
  cannot kill its mutant — the same silent failure in a smaller costume.
- **The byte budget is not load-bearing.** Given an absurd budget, the compile-
  and-halve fallback still produces only compilable chunks.

The fixture `tests/Fixtures/provider-covering-filters.txt` is the plugin's own
derived filter set for that file, captured from an instrumented run — not a
reconstruction.

## Proof 4, reproduced by hand

```bash
PROBE='ProviderAttributionProbeTest::(.*)it.registers.its.routes.when.boot.{1,2}.is.invoked.from.a.test.body'

# against the committed mutant -- fails
PEST_MUTATION_TESTING="$PWD/src/VouchServiceProvider.php" \
PEST_MUTATION_FILE="$PWD/docs/superpowers/mutation/upstream-defect/VouchServiceProvider.mutated.php" \
vendor/bin/pest "--filter=\"$PROBE\""

# against real source -- passes
vendor/bin/pest "--filter=\"$PROBE\""
```

Note that running the whole chunk under `--bail` stops at the *first* failure,
which is an unrelated test: a broken routes path breaks application boot widely.
That proves the kill but not the attribution, which is why the probe is asserted
on its own.

## If the patch ever has to be rebuilt

```bash
# regenerate against a pristine copy of the same version
diff -u a/src/MutationTest.php b/src/MutationTest.php \
  > patches/pest-plugin-mutate-3.0.5-chunk-filters.patch

# prove it applies from clean
rm -rf vendor/pestphp/pest-plugin-mutate && composer install
```

`composer install` prints `Applying patches for pestphp/pest-plugin-mutate` when
it works. Verified by removing the package directory and reinstalling.

## When to remove it

When an upstream release contains the fix: unpin the version, drop the
`extra.patches` entry, delete the patch file, and delete
`tests/Mutation/FilterChunkingTest.php`'s composer-declaration test. Keep the
reproduction test — it is the thing that will tell you whether the upstream fix
actually holds.

Task 13 does **not** wait on upstream. The patch is the control now.
