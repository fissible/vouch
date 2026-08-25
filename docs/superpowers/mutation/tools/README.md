# Survivor classification tooling

`classify-survivors.php` assigns a mechanical disposition to every row a
mutation run emits, so that ruling work is spent on rows that carry a verdict
rather than on rows the instrument was never able to reach.

## Why it exists

`UNCOVERED` is a routing limitation, not a judgement. The Kernel chunk made the
cost of confusing the two concrete: it reported 26 uncovered rows, and 25 of
them sat on lines that cannot be executed by any test — enum case declarations,
class constants, and the `match (true)` line itself. `TransitionRulesTest.php`
and `FactorStrengthTest.php` both exist and pass; the plugin still had nowhere
to route their mutants. Ruling those 25 by hand would have produced 25
individually-reasoned notes for a single mechanical fact.

The one row that survived that filter, `ErrorShaper.php:90`, is a real gap.

## Dispositions

| disposition | coverage evidence | meaning |
|---|---|---|
| `instrument-unroutable` | line absent from the map | not executable; no test can reach a mutant here |
| `never-executed` | line present, zero hits | executable and unreached — a genuine gap |
| `engine-gated` | zero hits here, executed on another engine | unreachable on this engine by construction |
| `executed-and-survived` | line present, hits > 0 | tests run it and the mutant lived; assertions are too weak |
| `indeterminate` | only a bare executed set was supplied | unroutable and gap cannot be separated |
| `inconsistent-map` | absent here, executed elsewhere | the maps disagree about what is executable |

Only `executed-and-survived` and `never-executed` are findings. The rest are
statements about the instrument.

`inconsistent-map` should not occur: identical source yields identical
executable lines on every engine. It exits 2 because it means one of the
coverage inputs is untrustworthy, and a disposition derived from an
untrustworthy map is worse than no disposition.

## Usage

```
php classify-survivors.php --log=FILE (--map=CLOVER | --lines=SET) \
    [--union=CLOVER]... [--source-root=DIR] [--emit-lines=FILE] \
    [--baseline=CLASSIFICATION.json]
    [--baseline-identity=line|expression] [--json]
```

Producing the inputs:

```bash
# The log must be non-compact. Parallel runs suppress the row list entirely.
vendor/bin/pest --mutate --path=src/Kernel --min=0 | tee kernel.log
sed -e 's/\x1b\[[0-9;]*m//g' kernel.log > kernel.txt

# The map must come from the same source state as the mutation run.
php -d pcov.enabled=1 -d pcov.directory=src vendor/bin/pest --coverage-clover=sqlite.xml
```

Every row is identified by `(file, mutator, expression)` as the ledger
requires, with the expression read from source rather than inferred, plus the
plugin's mutation ID as the tool-level key.

For a confirmation run, pass the prior classification with `--baseline`. The
report then includes `added` and `removed` row identities keyed by
`(file, line, mutator)` by default. When a baseline was taken at a different
source SHA and code above a row moved, pass
`--baseline-identity=expression` to compare `(file, mutator, expression)`
instead. The expression mode is intentionally explicit: within one source
state duplicate expressions can occur on distinct rows, so line-keying remains
the safe default. This identity diff is the required comparison: a
stable aggregate can hide a survivor replacing a kill, while a row diff makes
both directions explicit. JSON mode returns `{rows, baseline_diff}` when this
option is supplied.

Classification artifacts therefore have two supported shapes: older runs are
bare row lists, while runs made with `--baseline` are wrapped as
`{rows, baseline_diff}`. Consumers must read `$decoded['rows'] ?? $decoded`
rather than assuming one shape.

This tool's dispositions are evidence-driven and have been corrected three
times by real measurements: plugin state now outranks conflicting line
coverage for `UNTESTED` rows; timeout glyphs are recovered positionally from
their `RUN` heading; and confirmation changes are compared by row identity
rather than aggregate counts. Those cases are part of the tool's authority
boundary, not implementation trivia. A future classifier change must preserve
their tests before its output is used as reconciliation evidence.

## Engine union

A row is engine-gated only when another engine executes what the measuring
engine could not, so `--union` deliberately excludes the measuring map.
`--emit-lines` writes the unioned executed set for reuse, which avoids
re-parsing three Clover reports for every chunk.

`DatabaseAuthThrottleStore::ensureIpParent()` is the reference case:
`ensureIpParent()` returns early on SQLite, so its committed-row branch is
never executed under the measuring engine and never executable under MySQL's.
Validate the union against that branch before trusting it on rows whose
behaviour has not already been reasoned about.

## Test

```
php classify-survivors.test.php
```

Self-contained, with no Pest or PHPUnit dependency: the reconciliation pin
guards `src/`, `tests/`, `composer.*`, `phpunit.xml`, `pest.php`, `config/` and
`database/`, and this tool must be landable without disturbing any of them.

The suite is hermetic apart from one reality anchor, which asserts that
`ensureIpParent()` still returns early on SQLite ahead of the committed-row
branch. It is written as a content match rather than a line match so that
editing around it does not fail the test, while removing the engine gate does.
