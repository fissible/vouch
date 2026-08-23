# Kernel mutation manifest — baseline `66ac67d`

Measurement was run at documentation HEAD `aa04377` with a source-equivalence
guard proving no `src/`, `tests/`, dependency, configuration, or database drift
from `66ac67d`.

Literal command:

```text
vendor/bin/pest --mutate --path=src/Kernel --no-cache --min=0
```

The path-scoped run is authoritative. An earlier exact-class probe using
`--class='Fissible\\Vouch\\Kernel'` generated zero mutations because the
plugin's class filter does not match nested namespace declarations; that probe
is discarded as an instrument failure.

| field | value |
|---|---|
| generated | 236 mutations / 13 RUN files |
| tested | 205 |
| untested | 5 |
| uncovered | 26 |
| timeouts | 0 |
| elapsed | 161.87s |
| baseline suite | 1,161 tests / 4,092 assertions / 31.54s |
| timeout threshold | 37.85s |
| clean log SHA-256 | `c1344591f4657c44667a7b5277f07abcd70aafa8402b8726bcb065cc55a80228` |
| Clover SHA-256 | `3851a6824d48eab016cd005a28ad4c36bb62bcfee773936b8442e987034f6b60` |

## Rows requiring disposition

| result | file | mutator | expression |
|---|---|---|---|
| UNTESTED | `src/Kernel/Assurance/AssuranceFacts.php` | TrueToFalse | `$credentialIds[$factor->credentialId] = true;` |
| UNTESTED | `src/Kernel/Assurance/AssuranceFacts.php` | UnwrapArrayValues | `$eligible = array_values(array_filter($factors, ...));` |
| UNTESTED | `src/Kernel/Assurance/AssuranceLevel.php` | RemoveEarlyReturn | `return false;` |
| UNCOVERED | `src/Kernel/Attempt/TransitionRules.php` | RemoveArrayItem (10 rows) | `private const FORWARD = [...]` |
| UNCOVERED | `src/Kernel/Attempt/TransitionRules.php` | RemoveArrayItem (4 rows) | `private const TERMINAL = [...]` |
| UNTESTED | `src/Kernel/Attempt/TransitionRules.php` | RemoveEarlyReturn | `return false;` |
| UNCOVERED | `src/Kernel/Enumeration/ErrorShaper.php` | RemoveEarlyReturn | `return null;` |
| UNCOVERED | `src/Kernel/Factor/FactorStrength.php` | DecrementInteger / IncrementInteger (10 each) | enum case declarations |
| UNCOVERED | `src/Kernel/Satisfiability/SatisfiabilityEvaluator.php` | TrueToFalse | `return match (true) {` |
| UNTESTED | `src/Kernel/Satisfiability/SatisfiabilityEvaluator.php` | UnwrapArrayValues | `$eligible = array_values(array_filter($satisfied, ...));` |

Coverage inspection classifies 25 uncovered rows as
**instrument-unroutable**: declaration lines in `TransitionRules` and
`FactorStrength`, plus the `match` line in `SatisfiabilityEvaluator` absent from
the coverage map while all match arms are executed. The remaining uncovered row
is a genuine gap at `ErrorShaper::strictLockRetry()` (`return null;`), where a
focused strict-posture test is queued and must not be landed during the pinned
measurement sequence.

The five UNTESTED rows are on executed lines and remain genuine survivor
candidates. Their final dispositions must use stable
`(file, mutator, expression)` membership.
