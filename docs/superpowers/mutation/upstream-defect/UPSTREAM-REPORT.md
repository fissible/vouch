# Upstream report — pest-plugin-mutate reports untested mutants when the derived `--filter` exceeds PCRE's compile limit

Self-contained. Nothing below depends on this codebase.

- `pestphp/pest` v3.8.7
- `pestphp/pest-plugin-mutate` v3.0.5
- `phpunit/phpunit` (bundled), PHP 8.4.24, PCRE2 10.47

## Summary

For each mutant the plugin spawns a child with a single `--filter` regex
alternating **every test that covers the mutated lines**. When enough tests cover
one file, that pattern grows past what PCRE will compile. PHPUnit suppresses the
compilation failure and treats it as "no test matched", so the child selects zero
tests and exits 0 — which the plugin scores as a **surviving mutant**.

The result is silent and inverted: the better covered a file is, the more likely
its mutants are reported as untested. In our case a service provider covered by
453 tests reported 56 untested mutants, of which **42 are killed** once the
filter is split.

## Mechanism

1. `src/MutationTest.php:52-62` builds one filter per covering test and
   `:89` joins them: `'--filter="'.implode('|', $filters).'"'`.
2. With 453 covering tests the pattern is 37,818 bytes. PCRE refuses it:
   `preg_match(): Compilation failed: regular expression is too large at offset 0`
3. `phpunit/src/Runner/Filter/NameFilterIterator.php:66` is
   `@preg_match($this->regularExpression, $name, $matches) === 1`.
   The `@` suppresses the warning; `false === 1` is false. Every test is rejected
   for the same reason a genuinely non-matching test is rejected.
4. The child prints `INFO No tests found.` and exits **0**.
5. `MutationTest::hasFinished()` treats `isSuccessful()` as survival and records
   `MutationTestResult::Untested`.

A passing suite and a silently empty suite are the same exit code, and nothing
between them checks that any test actually ran.

## Minimal reproduction (no Pest required)

```php
<?php
// Build the same shape of filter the plugin builds, at the same scale.
$filters = [];
for ($i = 0; $i < 453; $i++) {
    $filters[] = "SomeQuiteLongTestClassName{$i}::(.*)it.does.a.thing.with.a.fairly.long.name.{$i}";
}
$pattern = '"' . implode('|', $filters) . '"';   // exactly MutationTest.php:89

var_dump(strlen($pattern));                       // ~37000+
var_dump(@preg_match($pattern, 'SomeQuiteLongTestClassName0::it_does_a_thing'));
var_dump(preg_last_error_msg());
// bool(false)
// string(14) "Internal error"
//   with the warning: "Compilation failed: regular expression is too large"
```

Because `NameFilterIterator` compares `=== 1`, that `false` silently rejects
every test name.

### Threshold, bisected on the real filter set

| alternations | pattern bytes | `preg_match` |
|---|---|---|
| 409 | 34,140 | compiles |
| 410 | 34,222 | `false` — "regular expression is too large" |

- Not the JIT: identical at `pcre.jit=0`.
- Not the capturing groups: `(?:.*)` and bare `.*` both still fail.
- Not tunable from `php.ini` — it is a PCRE2 compiled-size limit, and the limit
  is on the *compiled* pattern, so no source-byte figure is portable.

### End-to-end, if you want to see it in the runner

Any project where one source file is covered by ~450+ tests will do; a service
provider or a bootstrap file reaches that easily. Run the mutation suite scoped
to that file and every mutant in it comes back `UNTESTED` while the child output
says `No tests found.`

## Suggested fix

Split the derived filters into chunks that compile, and require **every** chunk
to pass before recording survival — the first chunk that fails has killed the
mutant. This preserves the tool's causal signal exactly; it only stops handing
PCRE a pattern it cannot compile.

Two details worth keeping:

- Verify each chunk by actually compiling it and halve anything that still
  fails, rather than trusting a byte budget. The limit applies to the compiled
  pattern, so byte counts are only a proxy.
- A file whose filter already compiles must produce exactly one chunk, so the
  common path is unchanged.

A patch implementing this against v3.0.5 is in this repository at
`patches/pest-plugin-mutate-3.0.5-chunk-filters.patch`, together with tests in
`tests/Mutation/FilterChunkingTest.php` covering the split, its losslessness, the
single-chunk fast path, and the fallback when the byte budget is wrong.

## Separately worth hardening

Even with chunking, `MutationTest::hasFinished()` cannot distinguish "the
covering tests passed" from "no tests ran". Treating a child that executed zero
tests as an error rather than as a survivor would have surfaced this immediately
instead of as 56 plausible-looking survivors. PHPUnit exits 0 for an empty run by
default; `--fail-on-empty-test-suite` is available.
