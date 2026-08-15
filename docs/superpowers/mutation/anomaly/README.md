# Unexplained mutation-run discrepancy — 56 provider rows

**Not a disposition. Not a kill. An open anomaly with a reproduction.**

`src/VouchServiceProvider.php` yields 56 `UNTESTED` mutations in the aggregate
plugin run. A faithfully reproduced child, using the plugin's own derived filter
and mutation-file environment, **kills** them. The cause of the difference is not
identified.

## Environment

```
pestphp/pest              v3.8.7
pestphp/pest-plugin-mutate v3.0.5
PHP 8.4.24 (cli, NTS)
```

## Parent argv (aggregate run)

```
vendor/bin/pest --mutate --class="Fissible\Vouch" --ignore="Kernel"
```

Result: 1314 mutations / 60 files / 0 fatals / 814s / 75.88%.
`src/VouchServiceProvider.php` → 56 `UNTESTED`, 6 `UNCOVERED`, 7 tested.

## The specific mutation

```
UNTESTED  src/VouchServiceProvider.php  > Line 227: RemoveMethodCall - ID: 7f096b01bc284cb7
```

Source line: `$this->loadRoutesFrom(__DIR__ . '/../routes/vouch.php');`

## Coverage entry the plugin consumes

`$codeCoverage->getData()->lineCoverage()` for that file, line 227:

```
P\Tests\Database\ProviderAttributionProbeTest::__pest_evaluable_it_registers_its_routes_when_boot___is_invoked_from_a_test_body
```

## Derived child filter

Produced by the plugin's own transformation at `MutationTest.php:56`:

```
ProviderAttributionProbeTest::(.*)it.registers.its.routes.when.boot.{1,2}.is.invoked.from.a.test.body
```

## Reproduction that KILLS

```bash
PEST_MUTATION_TESTING="<abs>/src/VouchServiceProvider.php" \
PEST_MUTATION_FILE="<abs>/docs/superpowers/mutation/anomaly/VouchServiceProvider.mutated.php" \
vendor/bin/pest --bail "--filter=<derived filter above>"
```

→ `Tests: 1 failed`. Identical with the plugin's literal-quoted
`--filter="…"` argv form.

The mutated copy is committed beside this file.

## Layers tested, all correct

Coverage attribution · filter derivation · filter selection · filter
discrimination · literal-quote argv form · inherited scope options (stripped by
`MutateOption`/`ClassOption`/`IgnoreOption`) · mutation-file interception.

## Independent behavioural evidence for the same rows

- `ProviderEffectTest` — config, migrations, routes, publish sources, bindings,
  middleware group, aliases, console command.
- Per-expression probes — 11 to 19 failures each.
- Whole-suite probe with the routes path broken — **530 failed**.
- `ProviderAttributionProbeTest` — `boot()` invoked in a test body against an
  emptied route collection.

## Status

The provider wiring is well tested. The instrument is not trustworthy enough to
certify these rows, so they are **neither killed nor dispositioned**. They are
carried as an open anomaly until the discrepancy is resolved or an alternative
control is explicitly accepted in its place.
